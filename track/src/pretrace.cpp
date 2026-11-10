#include "pin.H"
#include "taint_core.hpp"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_set>
#include <map>
#include <tuple>
#include <csignal>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

using namespace pre;
KNOB<std::string> Output(KNOB_MODE_WRITEONCE, "pintool", "o", "trace.jsonl", "JSONL output");
KNOB<INT32> Fd(KNOB_MODE_WRITEONCE, "pintool", "fd", "-1", "Only this input fd; -1 selects sockets");
KNOB<BOOL> AllReads(KNOB_MODE_WRITEONCE, "pintool", "all-reads", "0", "Also taint file/pipe/stdin reads");
KNOB<BOOL> Values(KNOB_MODE_WRITEONCE, "pintool", "values", "1", "Record operand values before execution");
KNOB<BOOL> Flow(KNOB_MODE_WRITEONCE, "pintool", "flow", "1",
                "Record main executable control flow after first input");
KNOB<BOOL> Strict(KNOB_MODE_WRITEONCE, "pintool", "strict", "0",
                  "Abort on tainted conservative fallback or collection gap");
KNOB<BOOL> AddressLoads(KNOB_MODE_WRITEONCE, "pintool", "address-loads", "0",
                        "Conservatively include address provenance in loaded data");
KNOB<std::string> AddressLoadPolicy(KNOB_MODE_WRITEONCE, "pintool", "address-load-policy", "all",
                                   "Address load sources: all or index_only (syntactic index register)");
KNOB<std::string> StopMarker(KNOB_MODE_WRITEONCE, "pintool", "stop-marker", "",
                            "Runner-owned replay completion marker; classify first matching SIGTERM");
static bool stop_marker_consumed = false;
KNOB<UINT32> MaxInput(KNOB_MODE_WRITEONCE, "pintool", "max-input", "1048576",
                      "Maximum tainted bytes per receive (truncation logged)");
KNOB<UINT64> MaxEvents(KNOB_MODE_WRITEONCE, "pintool", "max-events", "0",
                       "Stop explicitly after this many dynamic events; 0 unlimited");

KNOB<BOOL> ComparisonModels(KNOB_MODE_WRITEONCE, "pintool", "comparison-models", "1",
                            "Conservative ABI summaries for imported strcmp/strncmp/memcmp/bcmp");
static FILE *out;
static PIN_LOCK lock;
static TLS_KEY tls;
static Tags tags;
static Shadow shadow;
static std::atomic<bool> active{false};
static std::unordered_set<int> sockets;
static uint32_t input_id = 0;
static uint64_t events = 0, fallback_events = 0, gaps = 0, next_ins = 0;
static size_t emitted_tags = 1;
static char output_buffer[1 << 20];
struct Guard {
    explicit Guard(THREADID t) {
        PIN_GetLock(&lock, t + 1);
    }
    ~Guard() {
        PIN_ReleaseLock(&lock);
    }
};
struct Span {
    ADDRINT addr;
    size_t size;
};
struct ComparisonFrame { ADDRINT ip, sp; Tag tag; size_t bytes; std::string name; };
struct OutputSnapshot { ADDRINT address; std::vector<unsigned char> bytes; std::vector<Tag> tags; };
struct Thread {
    std::array<Bytes, REG_LAST> regs{};
    ADDRINT syscall = 0, args[6]{};
    std::vector<Span> spans;
    Tag length = 0;
    std::vector<ComparisonFrame> comparisons;
    std::vector<OutputSnapshot> outputs;
    std::string fd_kind;
};
static Thread *state(THREADID t) {
    return static_cast<Thread *>(PIN_GetThreadData(tls, t));
}
static std::string quote(const std::string &s) {
    std::string r = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') {
            r += '\\';
            r += c;
        } else if (c < 32) {
            char b[7];
            snprintf(b, sizeof b, "\\u%04x", c);
            r += b;
        } else
            r += c;
    }
    return r + '"';
}
static void fatal(const char *msg) {
    fprintf(stderr, "pretrace: %s\n", msg);
    if (out)
        fflush(out);
    PIN_ExitProcess(2);
}
static void gap(const char *reason) {
    ++gaps;
    fprintf(out, "{\"type\":\"gap\",\"reason\":%s}\n", quote(reason).c_str());
    if (Strict.Value())
        fatal(reason);
}
static void definitions() {
    while (emitted_tags < tags.size()) {
        auto id = emitted_tags++;
        fprintf(out, "{\"type\":\"tag\",\"id\":%zu,\"origins\":[", id);
        bool first = true;
        for (auto x : tags.get(id)) {
            fprintf(out, "%s[%u,%u]", first ? "" : ",", unsigned(x >> 32), unsigned(x));
            first = false;
        }
        fputs("]}\n", out);
    }
}
static void event_count() {
    ++events;
    if (ferror(out))
        fatal("output write failed");
    if (MaxEvents.Value() && events >= MaxEvents.Value()) {
        gap("max-events reached; trace incomplete");
        fatal("max-events reached");
    }
}
static void hex_value(const unsigned char *p, size_t n) {
    fputc('"', out);
    for (size_t j = 0; j < n; ++j)
        fprintf(out, "%02x", p[j]);
    fputc('"', out);
}
static void tag_array(const Bytes &b, size_t n) {
    fputc('[', out);
    for (size_t i = 0; i < n; ++i)
        fprintf(out, "%s%u", i ? "," : "", b[i]);
    fputc(']', out);
}
static bool tracked(REG r) {
    return REG_valid(r) &&
           (REG_is_gr(REG_FullRegName(r)) || REG_is_xmm_ymm_zmm(r) || r == REG_RFLAGS || r == REG_EFLAGS);
}
static REG canonical(REG r) {
    if (REG_is_xmm(r))
        return REG(REG_ZMM0 + (r - REG_XMM0));
    if (REG_is_ymm(r))
        return REG(REG_ZMM0 + (r - REG_YMM0));
    return REG_FullRegName(r);
}
struct Operand {
    REG reg = REG_INVALID();
    REG full = REG_INVALID();
    REG base = REG_INVALID(), index = REG_INVALID();
    unsigned width = 0, offset = 0;
    int mem = -1;
    bool read = false, write = false, zero = false, implicit = false, flags = false;
    std::string name;
};
enum class Mode {
    Generic,
    Copy,
    Sign,
    Swap,
    Zero,
    Shift,
    Bitwise,
    Exchange,
    Lea,
    StringCopy,
    Push,
    Pop,
    Compare,
    Bytewise,
    Mask,
    Arithmetic,
    ClearUpper
};
struct Plan {
    uint64_t id = 0;
    ADDRINT ip = 0, relative = 0, next = 0;
    bool call = false, ret = false;
    std::string text, image, routine;
    std::vector<Operand> ops;
    Mode mode = Mode::Generic;
    xed_iclass_enum_t opcode = XED_ICLASS_INVALID;
    bool imm = false, vex = false, control = false, main = false, emitted = false, conditional = false;
    bool unsupported = false;
    uint64_t immediate = 0;
    REG base = REG_INVALID(), index = REG_INVALID();
};
static std::vector<std::unique_ptr<Plan>> plans;
// Pin can instrument multiple code-cache copies of the same original instruction.
// Image ID separates unload/reload; instruction bytes separate code versions.
using PlanKey = std::tuple<UINT32, ADDRINT, std::string>;
static std::map<PlanKey, Plan *> plan_cache;
static Bytes read_reg(Thread &t, REG r) {
    Bytes b{};
    if (!tracked(r))
        return b;
    const auto &v = t.regs[canonical(r)];
    unsigned off = REG_is_Upper8(r) ? 1 : 0;
    std::copy_n(v.begin() + off, std::min<unsigned>(REG_Size(r), 64 - off), b.begin());
    return b;
}
static void clear_reg(Thread &t, REG r) {
    t.regs[canonical(r)].fill(0);
}
static void emit_plan(Plan &p) {
    if (p.emitted)
        return;
    p.emitted = true;
    fprintf(out,
            "{\"type\":\"instruction\",\"id\":%llu,\"ip\":%llu,\"image\":%s,\"image_offset\":%llu,"
            "\"routine\":%s,\"routine_source\":\"pin_symbol_hint\",\"routine_verified\":false,\"asm\":%s,\"operands\":[",
            (unsigned long long)p.id, (unsigned long long)p.ip, quote(p.image).c_str(),
            (unsigned long long)p.relative, quote(p.routine).c_str(), quote(p.text).c_str());
    for (size_t i = 0; i < p.ops.size(); ++i) {
        auto &o = p.ops[i];
        fprintf(out, "%s{\"name\":%s,\"width\":%u,\"read\":%s,\"write\":%s}", i ? "," : "",
                quote(o.name).c_str(), o.width, o.read ? "true" : "false", o.write ? "true" : "false");
    }
    fputs("]}\n", out);
}
#include "comparison_model.hpp"

static void analyze(THREADID tid, Plan *p, ADDRINT m0, ADDRINT m1, const CONTEXT *ctx, BOOL taken,
                    ADDRINT target) {
    if (!active.load(std::memory_order_relaxed))
        return;
    Thread &t = *state(tid);
    Guard guard(tid);
    comparison_before(t, tid, p, ctx, target);
    std::array<Bytes, 16> before{}, after{};
    std::array<Bytes, 16> inputs{};
    Tag all = 0, old = 0, address_tags = 0;
    std::array<Tag, 16> addresses{};
    std::array<Tag, 16> bases{}, indices{}, load_addresses{};
    int dest = -1, source = -1;
    ADDRINT mem[2] = {m0, m1};
    for (size_t i = 0; i < p->ops.size(); ++i) {
        auto &o = p->ops[i];
        before[i] = o.mem >= 0 ? shadow.read(mem[o.mem], o.width) : read_reg(t, o.reg);
        after[i] = before[i];
        if (o.mem >= 0) {
            if (tracked(o.base))
                bases[i] = tags.fold(read_reg(t, o.base), REG_Size(o.base));
            if (tracked(o.index))
                indices[i] = tags.fold(read_reg(t, o.index), REG_Size(o.index));
            addresses[i] = tags.join(bases[i], indices[i]);
            if (AddressLoads.Value() && o.read)
                load_addresses[i] = AddressLoadPolicy.Value() == "index_only" ? indices[i] : addresses[i];
        }
        address_tags = tags.join(address_tags, addresses[i]);
        inputs[i] = before[i];
        if (load_addresses[i])
            for (unsigned b = 0; b < o.width; ++b)
                inputs[i][b] = tags.join(inputs[i][b], load_addresses[i]);
        if (o.read) {
            all = tags.join(all, tags.fold(inputs[i], o.width));
            if (!o.flags && !o.implicit)
                source = i;
        }
        if (o.write) {
            old = tags.join(old, tags.fold(before[i], o.width));
            if (!o.flags && !o.implicit && dest < 0)
                dest = i;
        }
    }
    if (dest >= 0) {
        source = -1;
        for (size_t i = 0; i < p->ops.size(); ++i)
            if (int(i) != dest && p->ops[i].read && !p->ops[i].flags && !p->ops[i].implicit)
                source = i;
    }
    // Generic propagation is a conservative explicit-data union, never silently called exact.
    bool address_load = false;
    for (size_t i = 0; i < p->ops.size(); ++i)
        address_load |= load_addresses[i] != 0;
    bool fallback = (p->mode == Mode::Generic && !p->control) || address_load;
    for (size_t i = 0; i < p->ops.size(); ++i)
        if (p->ops[i].write)
            after[i].fill(all);
    if (p->opcode == XED_ICLASS_CLD || p->opcode == XED_ICLASS_STD || p->opcode == XED_ICLASS_CLC ||
        p->opcode == XED_ICLASS_STC || p->opcode == XED_ICLASS_CMC)
        for (size_t i = 0; i < p->ops.size(); ++i)
            if (p->ops[i].flags)
                after[i] = before[i];
    if (p->mode == Mode::Copy || p->mode == Mode::Sign || p->mode == Mode::Push || p->mode == Mode::Pop ||
        p->mode == Mode::StringCopy) {
        int s = -1;
        for (size_t i = 0; i < p->ops.size(); ++i) {
            const auto &o = p->ops[i];
            if (o.read && !o.flags && (o.mem >= 0 || !o.implicit))
                s = i;
        }
        for (size_t i = 0; i < p->ops.size(); ++i) {
            const auto &o = p->ops[i];
            if (!o.write)
                continue;
            if (o.implicit && o.mem < 0 && !o.flags) {
                after[i] = before[i];
                continue;
            }
            after[i] = s < 0 ? Bytes{} : extend(inputs[s], p->ops[s].width, o.width, p->mode == Mode::Sign);
        }
    } else if (p->mode == Mode::Zero) {
        for (size_t i = 0; i < p->ops.size(); ++i)
            if (p->ops[i].write)
                after[i].fill(0);
    } else if (p->mode == Mode::Swap && dest >= 0) {
        after[dest] = before[dest];
        std::reverse(after[dest].begin(), after[dest].begin() + p->ops[dest].width);
    } else if (p->mode == Mode::Exchange && p->ops.size() >= 2) {
        after[0] = inputs[1];
        after[1] = inputs[0];
    } else if (p->mode == Mode::Lea && dest >= 0) {
        Tag a = 0;
        for (REG r : {p->base, p->index})
            if (tracked(r))
                a = tags.join(a, tags.fold(read_reg(t, r), REG_Size(r)));
        all = tags.join(all, a);
        after[dest].fill(a);
    } else if (p->mode == Mode::Bytewise && dest >= 0) {
        after[dest].fill(0);
        for (size_t i = 0; i < p->ops.size(); ++i)
            if (p->ops[i].read && !p->ops[i].flags)
                for (unsigned b = 0; b < p->ops[dest].width; ++b)
                    after[dest][b] = tags.join(after[dest][b], inputs[i][b]);
    } else if (p->mode == Mode::Mask && dest >= 0 && source >= 0) {
        after[dest].fill(0);
        for (unsigned b = 0; b < p->ops[source].width; ++b)
            after[dest][b / 8] = tags.join(after[dest][b / 8], inputs[source][b]);
    } else if (p->mode == Mode::Bitwise && dest >= 0) {
        auto &o = p->ops[dest];
        after[dest] = inputs[dest];
        for (size_t i = 0; i < o.width; ++i) {
            if (p->imm) {
                unsigned b = (p->immediate >> (8 * (i % 8))) & 255;
                if ((p->opcode == XED_ICLASS_AND && b == 0) || (p->opcode == XED_ICLASS_OR && b == 255))
                    after[dest][i] = 0;
            } else if (source >= 0)
                after[dest][i] = tags.join(inputs[dest][i], inputs[source][i]);
        }
    } else if (p->mode == Mode::Shift && dest >= 0) {
        unsigned count = p->imm ? p->immediate : PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX);
        auto op = p->opcode;
        after[dest] =
            shift(tags, inputs[dest], p->ops[dest].width, count, op == XED_ICLASS_SHL || op == XED_ICLASS_ROL,
                  op == XED_ICLASS_SAR, op == XED_ICLASS_ROL || op == XED_ICLASS_ROR);
        if (!p->imm) {
            Tag c = tags.fold(read_reg(t, REG_CL), 1);
            for (size_t i = 0; i < p->ops[dest].width; ++i)
                after[dest][i] = tags.join(after[dest][i], c);
        }
        if (!(count & (p->ops[dest].width == 8 ? 63 : 31)))
            for (size_t i = 0; i < p->ops.size(); ++i)
                if (p->ops[i].flags)
                    after[i] = before[i];
    }
    if (p->mode == Mode::ClearUpper)
        for (size_t i = 0; i < p->ops.size(); ++i) {
            after[i] = before[i];
            std::fill(after[i].begin() + (p->opcode == XED_ICLASS_VZEROALL ? 0 : 16), after[i].end(), 0);
        }
    // CALL writes a constant return address. Branches never propagate flags into RIP/RSP.
    if (p->control)
        for (size_t i = 0; i < p->ops.size(); ++i)
            if (p->ops[i].write)
                after[i] = p->ops[i].mem >= 0 ? Bytes{} : before[i];
    bool relevant = all || old || address_tags;
    bool flow = Flow.Value() && p->control && (p->main || all);
    if (relevant || flow) {
        emit_plan(*p);
        definitions();
        if (fallback && all) {
            ++fallback_events;
            if (Strict.Value())
                fatal("tainted instruction requires conservative propagation");
        }
        fprintf(out, "{\"type\":\"%s\",\"seq\":%llu,\"tid\":%u,\"ins\":%llu,\"policy\":\"%s\"",
                p->control ? "control" : "step", (unsigned long long)(events + 1), tid,
                (unsigned long long)p->id, fallback ? "conservative" : "modeled");
        fprintf(out, ",\"precision\":%s,\"address_to_data\":%s",
                quote(p->control ? "flags_or_target" :
                      p->mode == Mode::Generic || p->mode == Mode::Arithmetic ||
                      p->mode == Mode::Compare || p->mode == Mode::Lea ? "operand_union" :
                      p->mode == Mode::Bytewise ? "byte_lane" :
                      p->mode == Mode::Mask ? "mask_byte_union" : "modeled").c_str(),
                address_load ? "true" : "false");
        if (p->control)
            fprintf(out, ",\"taken\":%s,\"target\":%llu", taken ? "true" : "false",
                    (unsigned long long)target);
        fputs(",\"operands\":[", out);
        for (size_t i = 0; i < p->ops.size(); ++i) {
            auto &o = p->ops[i];
            if (i)
                fputc(',', out);
            fputs("{\"before\":", out);
            tag_array(before[i], o.width);
            if (o.write) {
                fputs(",\"after\":", out);
                tag_array(after[i], o.width);
            }
            if (o.mem >= 0)
                fprintf(out, ",\"address\":%llu,\"address_tag\":%u,\"base_tag\":%u,\"index_tag\":%u,\"load_address_tag\":%u",
                        (unsigned long long)mem[o.mem], addresses[i], bases[i], indices[i], load_addresses[i]);
            if (Values.Value()) {
                unsigned char value[64] = {};
                size_t n = o.width;
                if (o.mem >= 0)
                    n = PIN_SafeCopy(value, reinterpret_cast<void *>(mem[o.mem]), n);
                else
                    PIN_GetContextRegval(ctx, o.reg, value);
                fputs(",\"value_before\":", out);
                hex_value(value, n);
            }
            fputc('}', out);
        }
        fputs("]}\n", out);
        event_count();
    }
    for (size_t i = 0; i < p->ops.size(); ++i) {
        auto &o = p->ops[i];
        if (!o.write)
            continue;
        if (o.mem >= 0)
            shadow.write(mem[o.mem], after[i], o.width);
        else
            write_register(t.regs[o.full], o.offset, o.width, after[i], o.zero);
    }
}
static Operand regop(REG r, bool read, bool write, bool implicit, bool vex) {
    Operand o;
    o.reg = r;
    o.full = canonical(r);
    o.width = REG_Size(r);
    o.offset = REG_is_Upper8(r) ? 1 : 0;
    o.read = read;
    o.write = write;
    o.implicit = implicit && (o.full == LEVEL_BASE::REG_RSP || o.full == LEVEL_BASE::REG_RSI ||
                              o.full == LEVEL_BASE::REG_RDI || o.full == LEVEL_BASE::REG_RCX);
    o.flags = (o.full == REG_RFLAGS);
    o.name = REG_StringShort(r);
    o.zero = REG_is_gr32(r) || (vex && REG_is_xmm_ymm_zmm(r));
    return o;
}
static void unsupported_execution(THREADID tid, Plan *p) {
    if (!active.load(std::memory_order_relaxed))
        return;
    Guard g(tid);
    emit_plan(*p);
    ++gaps;
    fprintf(out,
            "{\"type\":\"gap\",\"ins\":%llu,\"reason\":\"executed instruction exceeds operand model\"}\n",
            (unsigned long long)p->id);
    if (Strict.Value())
        fatal("executed instruction exceeds operand model");
}
static void instrument(INS ins, Plan *pp) {
    const Plan &p = *pp;
    unsigned memory = INS_MemoryOperandCount(ins);
    if (p.unsupported) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(unsupported_execution), IARG_THREAD_ID, IARG_PTR,
                                 pp, IARG_END);
        return;
    }
    IARGLIST args = IARGLIST_Alloc();
    IARGLIST_AddArguments(args, IARG_THREAD_ID, IARG_PTR, pp, IARG_END);
    if (memory > 0)
        IARGLIST_AddArguments(args, IARG_MEMORYOP_EA, 0, IARG_END);
    else
        IARGLIST_AddArguments(args, IARG_ADDRINT, 0, IARG_END);
    if (memory > 1)
        IARGLIST_AddArguments(args, IARG_MEMORYOP_EA, 1, IARG_END);
    else
        IARGLIST_AddArguments(args, IARG_ADDRINT, 0, IARG_END);
    IARGLIST_AddArguments(args, IARG_CONST_CONTEXT, IARG_END);
    if (p.control)
        IARGLIST_AddArguments(args, IARG_BRANCH_TAKEN, IARG_BRANCH_TARGET_ADDR, IARG_END);
    else
        IARGLIST_AddArguments(args, IARG_BOOL, FALSE, IARG_ADDRINT, 0, IARG_END);
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(analyze), IARG_IARGLIST, args, IARG_END);
    IARGLIST_Free(args);
}
static void instruction(INS ins, VOID *) {
    if (INS_IsSyscall(ins) || INS_IsNop(ins) || INS_IsPrefetch(ins))
        return;
    IMG identity = IMG_FindByAddress(INS_Address(ins));
    char bytes[15] = {};
    size_t size = PIN_SafeCopy(bytes, reinterpret_cast<void *>(INS_Address(ins)), INS_Size(ins));
    PlanKey key{IMG_Valid(identity) ? IMG_Id(identity) : 0, INS_Address(ins), std::string(bytes, size)};
    auto cached = plan_cache.find(key);
    if (cached != plan_cache.end()) {
        instrument(ins, cached->second);
        return;
    }
    std::unique_ptr<Plan> holder(new Plan);
    Plan &p = *holder;
    p.id = ++next_ins;
    p.ip = INS_Address(ins);
    p.next = INS_NextAddress(ins);
    p.call = INS_IsCall(ins);
    p.ret = INS_IsRet(ins);
    p.opcode = static_cast<xed_iclass_enum_t>(INS_Opcode(ins));
    p.text = INS_Disassemble(ins);
    p.control = INS_IsControlFlow(ins);
    p.conditional = INS_HasFallThrough(ins) && INS_IsBranch(ins);
    IMG img = IMG_FindByAddress(p.ip);
    if (IMG_Valid(img)) {
        p.image = IMG_Name(img);
        p.relative = p.ip - IMG_LowAddress(img);
        p.main = IMG_IsMainExecutable(img);
    }
    RTN r = INS_Rtn(ins);
    if (RTN_Valid(r))
        p.routine = RTN_Name(r);
    p.vex = INS_Mnemonic(ins).size() && INS_Mnemonic(ins)[0] == 'V';
    unsigned memory = INS_MemoryOperandCount(ins);
    bool unsupported = memory > 2;
    for (unsigned i = 0; i < INS_OperandCount(ins); ++i) {
        if (INS_OperandIsImmediate(ins, i)) {
            p.imm = true;
            p.immediate = INS_OperandImmediate(ins, i);
        }
        if (INS_OperandIsReg(ins, i)) {
            REG reg = INS_OperandReg(ins, i);
            if (REG_is_mm(reg) || (REG_is_fr(reg) && !REG_is_xmm_ymm_zmm(reg)) || REG_is_tmm(reg))
                unsupported = true;
            if (!tracked(reg))
                continue;
            auto o = regop(reg, INS_OperandRead(ins, i), INS_OperandWritten(ins, i),
                           INS_OperandIsImplicit(ins, i), p.vex);
            if (o.width > 64) {
                unsupported = true;
                continue;
            }
            p.ops.push_back(o);
        }
    }
    for (unsigned m = 0; m < std::min(memory, 2U); ++m) {
        Operand o;
        o.mem = m;
        o.width = INS_MemoryOperandSize(ins, m);
        o.name = "mem" + std::to_string(m);
        o.read = INS_MemoryOperandIsRead(ins, m);
        o.write = INS_MemoryOperandIsWritten(ins, m);
        unsigned opidx = INS_MemoryOperandIndexToOperandIndex(ins, m);
        o.base = INS_OperandMemoryBaseReg(ins, opidx);
        o.index = INS_OperandMemoryIndexReg(ins, opidx);
        if (o.width > 64) {
            unsupported = true;
            continue;
        }
        p.ops.push_back(o);
    }
    // Some implicit operands (notably RFLAGS) are exposed only by the register access API.
    for (unsigned rw = 0; rw < 2; ++rw)
        for (unsigned i = 0; i < (rw ? INS_MaxNumWRegs(ins) : INS_MaxNumRRegs(ins)); ++i) {
            REG reg = rw ? INS_RegW(ins, i) : INS_RegR(ins, i);
            if (!tracked(reg))
                continue;
            // Address-generation registers must not become data dependencies, except LEA.
            bool address = false;
            for (unsigned j = 0; j < INS_OperandCount(ins); ++j)
                if (INS_OperandIsMemory(ins, j))
                    if (reg == INS_OperandMemoryBaseReg(ins, j) || reg == INS_OperandMemoryIndexReg(ins, j))
                        address = true;
            if (address && !rw)
                continue;
            bool found = false;
            for (auto &o : p.ops)
                if (o.mem < 0 && o.full == canonical(reg)) {
                    found = true;
                    break;
                }
            if (!found && REG_Size(reg) <= 64)
                p.ops.push_back(regop(reg, !rw, rw, true, p.vex));
        }
    switch (p.opcode) {
    case XED_ICLASS_MOV:
    case XED_ICLASS_MOVZX:
    case XED_ICLASS_MOVD:
    case XED_ICLASS_MOVQ:
    case XED_ICLASS_MOVDQA:
    case XED_ICLASS_MOVDQU:
    case XED_ICLASS_MOVAPS:
    case XED_ICLASS_MOVUPS:
    case XED_ICLASS_MOVAPD:
    case XED_ICLASS_MOVUPD:
    case XED_ICLASS_VMOVDQA:
    case XED_ICLASS_VMOVDQU:
    case XED_ICLASS_VMOVAPS:
    case XED_ICLASS_VMOVUPS:
    case XED_ICLASS_VMOVAPD:
    case XED_ICLASS_VMOVUPD:
        p.mode = Mode::Copy;
        break;
    case XED_ICLASS_MOVSX:
    case XED_ICLASS_MOVSXD:
        p.mode = Mode::Sign;
        break;
    case XED_ICLASS_PUSH:
        p.mode = Mode::Push;
        break;
    case XED_ICLASS_POP:
        p.mode = Mode::Pop;
        break;
    case XED_ICLASS_MOVSB:
    case XED_ICLASS_MOVSW:
    case XED_ICLASS_MOVSD:
    case XED_ICLASS_MOVSQ:
        if (memory == 2)
            p.mode = Mode::StringCopy;
        break;
    case XED_ICLASS_STOSB:
    case XED_ICLASS_STOSW:
    case XED_ICLASS_STOSD:
    case XED_ICLASS_STOSQ:
    case XED_ICLASS_LODSB:
    case XED_ICLASS_LODSW:
    case XED_ICLASS_LODSD:
    case XED_ICLASS_LODSQ:
        p.mode = Mode::StringCopy;
        break;
    case XED_ICLASS_BSWAP:
        p.mode = Mode::Swap;
        break;
    case XED_ICLASS_XCHG:
        p.mode = Mode::Exchange;
        break;
    case XED_ICLASS_SHL:
    case XED_ICLASS_SHR:
    case XED_ICLASS_SAR:
    case XED_ICLASS_ROL:
    case XED_ICLASS_ROR:
        p.mode = Mode::Shift;
        break;
    case XED_ICLASS_AND:
    case XED_ICLASS_OR:
    case XED_ICLASS_XOR:
        p.mode = Mode::Bitwise;
        break;
    case XED_ICLASS_ADD:
    case XED_ICLASS_ADC:
    case XED_ICLASS_SUB:
    case XED_ICLASS_SBB:
    case XED_ICLASS_IMUL:
    case XED_ICLASS_MUL:
    case XED_ICLASS_DIV:
    case XED_ICLASS_IDIV:
    case XED_ICLASS_INC:
    case XED_ICLASS_DEC:
    case XED_ICLASS_NEG:
    case XED_ICLASS_NOT:
        p.mode = Mode::Arithmetic;
        break;
    case XED_ICLASS_CMP:
    case XED_ICLASS_TEST:
        p.mode = Mode::Compare;
        break;
    case XED_ICLASS_LEA:
        p.mode = Mode::Lea;
        for (unsigned i = 0; i < INS_OperandCount(ins); ++i)
            if (INS_OperandIsMemory(ins, i) || INS_OperandIsAddressGenerator(ins, i)) {
                p.base = INS_OperandMemoryBaseReg(ins, i);
                p.index = INS_OperandMemoryIndexReg(ins, i);
            }
        // LEA has address-generation operands, not memory accesses. Keep the
        // source registers visible to downstream explanation/slicing as data reads.
        for (REG reg : {p.base, p.index}) {
            if (!tracked(reg))
                continue;
            bool found = false;
            for (auto &o : p.ops)
                if (o.mem < 0 && o.reg == reg) {
                    o.read = true;
                    found = true;
                }
            if (!found)
                p.ops.push_back(regop(reg, true, false, false, p.vex));
        }
        break;
    case XED_ICLASS_PCMPEQB: case XED_ICLASS_VPCMPEQB:
    case XED_ICLASS_PCMPGTB: case XED_ICLASS_VPCMPGTB:
    case XED_ICLASS_PMINUB: case XED_ICLASS_VPMINUB:
    case XED_ICLASS_PMAXUB: case XED_ICLASS_VPMAXUB:
    case XED_ICLASS_PAND: case XED_ICLASS_VPAND:
    case XED_ICLASS_POR: case XED_ICLASS_VPOR:
    case XED_ICLASS_PXOR: case XED_ICLASS_VPXOR:
        p.mode = Mode::Bytewise;
        // AVX-512 masked variants require a separate mask model.
        for (unsigned i = 0; i < INS_MaxNumRRegs(ins); ++i)
            if (REG_is_k_mask(INS_RegR(ins, i)))
                unsupported = true;
        for (unsigned i = 0; i < INS_MaxNumWRegs(ins); ++i)
            if (REG_is_k_mask(INS_RegW(ins, i)))
                unsupported = true;
        break;
    case XED_ICLASS_PMOVMSKB: case XED_ICLASS_VPMOVMSKB:
        p.mode = Mode::Mask;
        break;
    default:
        break;
    }
    if (p.opcode == XED_ICLASS_MOVD || p.opcode == XED_ICLASS_MOVQ)
        for (auto &o : p.ops)
            if (o.mem < 0 && o.write && REG_is_xmm(o.reg))
                o.width = 16;
    if (INS_Category(ins) == XED_CATEGORY_CMOV)
        p.mode = Mode::Copy;
    if (p.opcode == XED_ICLASS_VMOVDQU8 || p.opcode == XED_ICLASS_VMOVDQU16 ||
        p.opcode == XED_ICLASS_VMOVDQU32 || p.opcode == XED_ICLASS_VMOVDQU64 ||
        p.opcode == XED_ICLASS_VMOVDQA32 || p.opcode == XED_ICLASS_VMOVDQA64) {
        bool masked = false;
        for (unsigned i = 0; i < INS_MaxNumRRegs(ins); ++i)
            if (REG_is_k_mask(INS_RegR(ins, i)))
                masked = true;
        if (!masked)
            p.mode = Mode::Copy;
    }
    if ((p.opcode == XED_ICLASS_XOR || p.opcode == XED_ICLASS_SUB || p.opcode == XED_ICLASS_PXOR ||
         p.opcode == XED_ICLASS_XORPS || p.opcode == XED_ICLASS_XORPD) &&
        INS_OperandCount(ins) >= 2 && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1) &&
        INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1))
        p.mode = Mode::Zero;
    if (p.opcode == XED_ICLASS_VPXOR && INS_OperandCount(ins) >= 3 &&
        INS_OperandIsReg(ins, 1) && INS_OperandIsReg(ins, 2) &&
        INS_OperandReg(ins, 1) == INS_OperandReg(ins, 2))
        p.mode = Mode::Zero;
    if (p.opcode == XED_ICLASS_VZEROUPPER || p.opcode == XED_ICLASS_VZEROALL) {
        p.mode = Mode::ClearUpper;
        p.ops.clear();
        for (int i = 0; i < 16; ++i)
            p.ops.push_back(regop(REG(REG_YMM0 + i), false, true, false, true));
    }
    p.unsupported = p.ops.size() > 16 || unsupported;
    Plan *pp = holder.get();
    if (p.unsupported) {
        Guard g(0);
        fprintf(out, "{\"type\":\"unsupported_static\",\"ip\":%llu,\"asm\":%s}\n",
                (unsigned long long)p.ip, quote(p.text).c_str());
    }
    plan_cache.emplace(key, pp);
    plans.push_back(std::move(holder));
    instrument(ins, pp);
}

static bool receive_call(ADDRINT n) {
    return n == SYS_read || n == SYS_pread64 || n == SYS_readv || n == SYS_recvfrom || n == SYS_recvmsg;
}
static void iovecs(Thread &t, ADDRINT addr, size_t count) {
    if (count > 1024) {
        gap("iovec count exceeds Linux UIO_MAXIOV");
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        struct iovec v{};
        if (PIN_SafeCopy(&v, reinterpret_cast<void *>(addr + i * sizeof v), sizeof v) != sizeof v) {
            gap("cannot snapshot iovec");
            return;
        }
        t.spans.push_back({reinterpret_cast<ADDRINT>(v.iov_base), v.iov_len});
    }
}
static bool send_call(ADDRINT n) {
    return n == SYS_write || n == SYS_writev || n == SYS_sendto || n == SYS_sendmsg;
}
static std::string fd_kind(int fd) {
    if (sockets.count(fd)) return "socket";
    char path[64], link[4096] = {};
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(path, link, sizeof link - 1);
    if (n < 0) return "unknown";
    if (!strncmp(link, "socket:[", 8)) return "socket";
    if (!strncmp(link, "pipe:[", 6)) return "pipe";
    return "file_or_device";
}
static void sys_enter(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD standard, VOID *) {
    Thread &t = *state(tid);
    t.syscall = PIN_GetSyscallNumber(ctx, standard);
    for (unsigned i = 0; i < 6; ++i)
        t.args[i] = PIN_GetSyscallArgument(ctx, standard, i);
    t.spans.clear();
    t.length = 0;
    t.outputs.clear();
    if (!receive_call(t.syscall) && !send_call(t.syscall)) return;
    Guard g(tid);
    t.fd_kind = fd_kind(t.args[0]);
    if (t.syscall == SYS_readv || t.syscall == SYS_writev)
        iovecs(t, t.args[1], t.args[2]);
    else if (t.syscall == SYS_recvmsg || t.syscall == SYS_sendmsg) {
        msghdr h{};
        if (PIN_SafeCopy(&h, reinterpret_cast<void *>(t.args[1]), sizeof h) == sizeof h)
            iovecs(t, reinterpret_cast<ADDRINT>(h.msg_iov), h.msg_iovlen);
        else
            gap("cannot snapshot msghdr");
    } else
        t.spans.push_back({t.args[1], t.args[2]});
    if (send_call(t.syscall) && active.load() && t.fd_kind == "socket") {
        size_t budget = MaxInput.Value();
        for (auto span : t.spans) {
            if (!budget) break;
            OutputSnapshot snapshot; snapshot.address = span.addr;
            size_t n = std::min(span.size, budget);
            snapshot.bytes.resize(n);
            n = PIN_SafeCopy(snapshot.bytes.data(), reinterpret_cast<void *>(span.addr), n);
            snapshot.bytes.resize(n);
            for (size_t i = 0; i < n; ++i) snapshot.tags.push_back(shadow.get(span.addr + i));
            t.outputs.push_back(std::move(snapshot));
            budget -= n;
            if (n < span.size) break;
        }
    }
    if (t.syscall != SYS_readv && t.syscall != SYS_recvmsg)
        t.length = tags.fold(read_reg(t, LEVEL_BASE::REG_RDX), 8);
}
static void sys_exit(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD standard, VOID *) {
    Thread &t = *state(tid);
    Guard g(tid);
    auto ret = static_cast<int64_t>(PIN_GetSyscallReturn(ctx, standard));
    int fd = t.args[0];
    clear_reg(t, LEVEL_BASE::REG_RAX);
    clear_reg(t, LEVEL_BASE::REG_RCX);
    clear_reg(t, LEVEL_BASE::REG_R11);
    if (ret >= 0) {
        if (t.syscall == SYS_socket || t.syscall == SYS_accept || t.syscall == SYS_accept4)
            sockets.insert(ret);
        else if (t.syscall == SYS_socketpair) {
            int pair[2];
            if (PIN_SafeCopy(pair, reinterpret_cast<void *>(t.args[3]), sizeof pair) == sizeof pair) {
                sockets.insert(pair[0]);
                sockets.insert(pair[1]);
            }
        } else if (t.syscall == SYS_dup || t.syscall == SYS_dup2 || t.syscall == SYS_dup3) {
            bool sock = sockets.count(fd);
            sockets.erase(ret);
            if (sock)
                sockets.insert(ret);
        } else if (t.syscall == SYS_fcntl && (t.args[1] == 0 || t.args[1] == 1030)) {
            if (sockets.count(fd))
                sockets.insert(ret);
        } else if (t.syscall == SYS_close)
            sockets.erase(fd);
        else if (t.syscall == SYS_munmap)
            shadow.clear(t.args[0], t.args[1]);
        else if (t.syscall == SYS_mmap)
            shadow.clear(ret, t.args[1]);
    }
    if (send_call(t.syscall) && ret > 0 && active.load() && t.fd_kind == "socket") {
        uint64_t offset = 0;
        definitions();
        for (const auto &snapshot : t.outputs) {
            size_t n = std::min<uint64_t>(snapshot.bytes.size(), ret - offset);
            // Bounded records permit byte-window pagination even for large output buffers.
            for (size_t start = 0; start < n; start += 64) {
                size_t size = std::min<size_t>(64, n - start);
                fprintf(out, "{\"type\":\"output\",\"seq\":%llu,\"tid\":%u,\"fd\":%d,\"syscall\":%llu,"
                             "\"offset\":%llu,\"returned\":%lld,\"address\":%llu,\"bytes\":",
                        (unsigned long long)(events + 1), tid, fd, (unsigned long long)t.syscall,
                        (unsigned long long)(offset + start), (long long)ret,
                        (unsigned long long)(snapshot.address + start));
                hex_value(snapshot.bytes.data() + start, size);
                fputs(",\"tags\":[", out);
                for (size_t i = 0; i < size; ++i) fprintf(out, "%s%u", i ? "," : "", snapshot.tags[start + i]);
                fputs("],\"capture\":\"syscall_entry_snapshot\"}\n", out);
                event_count();
            }
            offset += n;
            if (offset >= uint64_t(ret)) break;
        }
        if (offset < uint64_t(ret)) gap("output snapshot limited by max-input or safe-copy");
    }
    if (!receive_call(t.syscall) || ret <= 0)
        return;
    bool selected = Fd.Value() >= 0 ? fd == Fd.Value()
                                    : (AllReads.Value() || t.fd_kind == "socket" || t.syscall == SYS_recvfrom ||
                                       t.syscall == SYS_recvmsg);
    uint32_t id = 0;
    if (selected) {
        if (input_id == UINT32_MAX)
            fatal("input id exhausted");
        id = ++input_id;
        active.store(true, std::memory_order_relaxed);
    }
    uint64_t remaining = ret, offset = 0, tainted = 0;
    for (auto s : t.spans) {
        size_t n = std::min<uint64_t>(remaining, s.size);
        if (!n)
            continue;
        shadow.clear(s.addr, n); // kernel overwrites also remove old provenance for unselected input
        if (selected) {
            size_t keep = std::min<uint64_t>(n, offset < MaxInput.Value() ? MaxInput.Value() - offset : 0);
            std::vector<unsigned char> value(keep);
            size_t copied = keep ? PIN_SafeCopy(value.data(), reinterpret_cast<void *>(s.addr), keep) : 0;
            if (copied < keep)
                gap("short safe copy of successful receive");
            for (size_t i = 0; i < copied; ++i)
                shadow.set(s.addr + i, tags.source(id, offset + i));
            definitions();
            fprintf(out,
                    "{\"type\":\"input_chunk\",\"input\":%u,\"offset\":%llu,\"address\":%llu,\"bytes\":", id,
                    (unsigned long long)offset, (unsigned long long)s.addr);
            hex_value(value.data(), copied);
            fputs("}\n", out);
            tainted += copied;
        }
        offset += n;
        remaining -= n;
        if (!remaining)
            break;
    }
    if (selected) {
        fprintf(out,
                "{\"type\":\"input\",\"seq\":%llu,\"tid\":%u,\"id\":%u,\"fd\":%d,\"syscall\":%llu,"
                "\"returned\":%lld,\"stored\":%llu,\"tainted\":%llu,\"length_tag\":%u,\"flags\":%llu,\"source_kind\":%s,\"selection_reason\":%s}\n",
                (unsigned long long)(events + 1), tid, id, fd, (unsigned long long)t.syscall, (long long)ret,
                (unsigned long long)offset, (unsigned long long)tainted, t.length,
                (unsigned long long)(t.syscall == SYS_recvfrom  ? t.args[3]
                                     : t.syscall == SYS_recvmsg ? t.args[2]
                                                                : 0),
                quote(t.fd_kind).c_str(), quote(Fd.Value() >= 0 ? "explicit_fd" : AllReads.Value() ? "all_reads" : "automatic_socket").c_str());
        event_count();
        if (tainted < offset)
            gap("max-input or safe-copy limited input; untracked tail cleared");
        // MSG_TRUNC can legitimately report a datagram size larger than the buffers.
        if (remaining && t.syscall != SYS_recvfrom && t.syscall != SYS_recvmsg)
            gap("receive length exceeds snapshotted buffers");
    }
}
static void thread_start(THREADID tid, CONTEXT *, INT32, VOID *) {
    PIN_SetThreadData(tls, new Thread, tid);
}
static void thread_end(THREADID tid, const CONTEXT *, INT32, VOID *) {
    delete state(tid);
    PIN_SetThreadData(tls, nullptr, tid);
}
static void context_change(THREADID tid, CONTEXT_CHANGE_REASON reason, const CONTEXT *, CONTEXT *, INT32 info,
                           VOID *) {
    if (!active.load())
        return;
    if (reason == CONTEXT_CHANGE_REASON_SIGNAL || reason == CONTEXT_CHANGE_REASON_EXCEPTION) {
        Guard g(tid);
        bool expected = false;
        if (reason == CONTEXT_CHANGE_REASON_SIGNAL && info == SIGTERM && !stop_marker_consumed && !StopMarker.Value().empty()) {
            FILE *marker = fopen(StopMarker.Value().c_str(), "r");
            if (marker) {
                char text[32] = {};
                expected = fgets(text, sizeof text, marker) && !strcmp(text, "replay_complete\n");
                fclose(marker);
            }
            stop_marker_consumed = expected;
        }
        ++gaps;
        fprintf(out, "{\"type\":\"gap\",\"reason\":\"signal/exception: before-instruction updates are not rolled back\","
                     "\"tid\":%u,\"after_seq\":%llu,\"signal_or_exception\":%d,\"context_reason\":%d,"
                     "\"category\":%s,\"classification_basis\":%s}\n",
                tid, (unsigned long long)events, info, int(reason),
                quote(expected ? "expected_stop" : "execution").c_str(),
                quote(expected ? "replay_stop_marker" : "signal_or_exception").c_str());
        if (Strict.Value())
            fatal("signal/exception: before-instruction updates are not rolled back");
    }
}
static void fini(INT32 code, VOID *) {
    fprintf(out,
            "{\"type\":\"summary\",\"exit_code\":%d,\"inputs\":%u,\"events\":%llu,\"tags\":%zu,\"shadow_"
            "pages\":%zu,\"conservative_events\":%llu,\"gaps\":%llu}\n",
            code, input_id, (unsigned long long)events, tags.size() - 1, shadow.pages(),
            (unsigned long long)fallback_events, (unsigned long long)gaps);
    if (fclose(out) != 0) {
        out = nullptr;
        fatal("output close failed");
    }
    out = nullptr;
}
int main(int argc, char **argv) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        fprintf(stderr, "%s\n", KNOB_BASE::StringKnobSummary().c_str());
        PIN_ExitProcess(1);
        return 1;
    }
    if (!MaxInput.Value()) {
        fprintf(stderr, "max-input must be positive\n");
        PIN_ExitProcess(1);
        return 1;
    }
    if (AddressLoadPolicy.Value() != "all" && AddressLoadPolicy.Value() != "index_only") {
        fprintf(stderr, "address-load-policy must be all or index_only\n");
        return 1;
    }
    out = fopen(Output.Value().c_str(), "w");
    if (!out) {
        perror(Output.Value().c_str());
        PIN_ExitProcess(1);
        return 1;
    }
    setvbuf(out, output_buffer, _IOFBF, sizeof output_buffer);
    PIN_InitLock(&lock);
    tls = PIN_CreateThreadDataKey(nullptr);
    if (tls == INVALID_TLS_KEY)
        fatal("TLS allocation failed");
    fprintf(out, "{\"type\":\"header\",\"schema\":1,\"tool\":\"pretrace\",\"architecture\":\"linux-x86_64\","
          "\"model_revision\":4,\"comparison_models\":%s,\"output_capture\":true,\"address_loads\":%s,\"address_load_policy\":%s,"
          "\"semantics\":\"explicit byte provenance plus optional comparison ABI summaries; before execution\"}\n",
          ComparisonModels.Value() ? "true" : "false", AddressLoads.Value() ? "true" : "false", quote(AddressLoads.Value() ? AddressLoadPolicy.Value() : "off").c_str());
    PIN_AddThreadStartFunction(thread_start, nullptr);
    PIN_AddThreadFiniFunction(thread_end, nullptr);
    IMG_AddInstrumentFunction(comparison_image, nullptr);
    IMG_AddUnloadFunction(comparison_unload, nullptr);
    INS_AddInstrumentFunction(instruction, nullptr);
    PIN_AddSyscallEntryFunction(sys_enter, nullptr);
    PIN_AddSyscallExitFunction(sys_exit, nullptr);
    PIN_AddContextChangeFunction(context_change, nullptr);
    PIN_AddFiniFunction(fini, nullptr);
    PIN_StartProgram();
    return 0;
}
