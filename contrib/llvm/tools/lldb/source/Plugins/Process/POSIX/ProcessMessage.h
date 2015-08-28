//===-- ProcessMessage.h ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_ProcessMessage_H_
#define liblldb_ProcessMessage_H_

#include <cassert>

#include "lldb/lldb-defines.h"
#include "lldb/lldb-types.h"

class ProcessMessage
{
public:

    /// The type of signal this message can correspond to.
    enum Kind
    {
        eInvalidMessage,
        eAttachMessage,
        eExitMessage,
        eLimboMessage,
        eSignalMessage,
        eSignalDeliveredMessage,
        eTraceMessage,
        eBreakpointMessage,
        eWatchpointMessage,
        eCrashMessage,
        eNewThreadMessage,
        eExecMessage
    };

    enum CrashReason
    {
        eInvalidCrashReason,

        // SIGSEGV crash reasons.
        eInvalidAddress,
        ePrivilegedAddress,

        // SIGILL crash reasons.
        eIllegalOpcode,
        eIllegalOperand,
        eIllegalAddressingMode,
        eIllegalTrap,
        ePrivilegedOpcode,
        ePrivilegedRegister,
        eCoprocessorError,
        eInternalStackError,

        // SIGBUS crash reasons,
        eIllegalAlignment,
        eIllegalAddress,
        eHardwareError,

        // SIGFPE crash reasons,
        eIntegerDivideByZero,
        eIntegerOverflow,
        eFloatDivideByZero,
        eFloatOverflow,
        eFloatUnderflow,
        eFloatInexactResult,
        eFloatInvalidOperation,
        eFloatSubscriptRange
    };

    ProcessMessage()
        : m_tid(LLDB_INVALID_PROCESS_ID),
          m_kind(eInvalidMessage),
          m_crash_reason(eInvalidCrashReason),
          m_status(0),
          m_addr(0) { }

    Kind GetKind() const { return m_kind; }

    lldb::tid_t GetTID() const { return m_tid; }

    /// Indicates that the process @p pid has successfully attached.
    static ProcessMessage Attach(lldb::pid_t pid) {
        return ProcessMessage(pid, eAttachMessage);
    }

    /// Indicates that the thread @p tid is about to exit with status @p status.
    static ProcessMessage Limbo(lldb::tid_t tid, int status) {
        return ProcessMessage(tid, eLimboMessage, status);
    }

    /// Indicates that the thread @p tid had the signal @p signum delivered.
    static ProcessMessage Signal(lldb::tid_t tid, int signum) {
        return ProcessMessage(tid, eSignalMessage, signum);
    }

    /// Indicates that a signal @p signum generated by the debugging process was
    /// delivered to the thread @p tid.
    static ProcessMessage SignalDelivered(lldb::tid_t tid, int signum) {
        return ProcessMessage(tid, eSignalDeliveredMessage, signum);
    }

    /// Indicates that the thread @p tid encountered a trace point.
    static ProcessMessage Trace(lldb::tid_t tid) {
        return ProcessMessage(tid, eTraceMessage);
    }

    /// Indicates that the thread @p tid encountered a break point.
    static ProcessMessage Break(lldb::tid_t tid) {
        return ProcessMessage(tid, eBreakpointMessage);
    }

    static ProcessMessage Watch(lldb::tid_t tid, lldb::addr_t wp_addr) {
        return ProcessMessage(tid, eWatchpointMessage, 0, wp_addr);
    }

    /// Indicates that the thread @p tid crashed.
    static ProcessMessage Crash(lldb::pid_t pid, CrashReason reason,
                                int signo, lldb::addr_t fault_addr) {
        ProcessMessage message(pid, eCrashMessage, signo, fault_addr);
        message.m_crash_reason = reason;
        return message;
    }

    /// Indicates that the thread @p child_tid was spawned.
    static ProcessMessage NewThread(lldb::tid_t parent_tid, lldb::tid_t child_tid) {
        return ProcessMessage(parent_tid, eNewThreadMessage, child_tid);
    }

    /// Indicates that the thread @p tid is about to exit with status @p status.
    static ProcessMessage Exit(lldb::tid_t tid, int status) {
        return ProcessMessage(tid, eExitMessage, status);
    }

    /// Indicates that the thread @p pid has exec'd.
    static ProcessMessage Exec(lldb::tid_t tid) {
        return ProcessMessage(tid, eExecMessage);
    }

    int GetExitStatus() const {
        assert(GetKind() == eExitMessage || GetKind() == eLimboMessage);
        return m_status;
    }

    int GetSignal() const {
        assert(GetKind() == eSignalMessage || GetKind() == eCrashMessage ||
               GetKind() == eSignalDeliveredMessage);
        return m_status;
    }

    int GetStopStatus() const {
        assert(GetKind() == eSignalMessage);
        return m_status;
    }

    CrashReason GetCrashReason() const {
        assert(GetKind() == eCrashMessage);
        return m_crash_reason;
    }

    lldb::addr_t GetFaultAddress() const {
        assert(GetKind() == eCrashMessage);
        return m_addr;
    }

    lldb::addr_t GetHWAddress() const {
        assert(GetKind() == eWatchpointMessage || GetKind() == eTraceMessage);
        return m_addr;
    }

    lldb::tid_t GetChildTID() const {
        assert(GetKind() == eNewThreadMessage);
        return m_child_tid;
    }

    static const char *
    GetCrashReasonString(CrashReason reason, lldb::addr_t fault_addr);

    const char *
    PrintCrashReason() const;

    static const char *
    PrintCrashReason(CrashReason reason);

    const char *
    PrintKind() const;

    static const char *
    PrintKind(Kind);

private:
    ProcessMessage(lldb::tid_t tid, Kind kind, 
                   int status = 0, lldb::addr_t addr = 0)
        : m_tid(tid),
          m_kind(kind),
          m_crash_reason(eInvalidCrashReason),
          m_status(status),
          m_addr(addr),
          m_child_tid(0) { }

    ProcessMessage(lldb::tid_t tid, Kind kind, lldb::tid_t child_tid)
        : m_tid(tid),
          m_kind(kind),
          m_crash_reason(eInvalidCrashReason),
          m_status(0),
          m_addr(0),
          m_child_tid(child_tid) { }

    lldb::tid_t m_tid;
    Kind        m_kind         : 8;
    CrashReason m_crash_reason : 8;
    int m_status;
    lldb::addr_t m_addr;
    lldb::tid_t m_child_tid;
};

#endif // #ifndef liblldb_ProcessMessage_H_