#!/usr/bin/env python3
"""断言有效性验证 — 故意违反三个不变量，确认断言真的能抓住(而非形同虚设)
三个不变量:
  #1 call_context must be set before encrypt
  #2 DID must be resolved before ring (peer_did != placeholder)
  #3 prefix/encryption invariant broken (has_enc_prefix == e2ee_enabled)
用法: .venv/bin/python3 e2ee_assert_test.py
期望: 三个用例全部触发 AssertionError
"""
import sys, os, asyncio
SRC = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC)
from agentlink.secure_session import SecureSessionManager
from agentlink.p1_shim import AgentLinkState
from agentlink import (generate_keypair, compute_shared_secret,
                       derive_session_key, SessionCipher, _b64, _unb64)

FAILED = []

def expect_assert(name, fn):
    try:
        fn()
        FAILED.append(name); print(f"  ❌ {name}: 没触发断言（失效！）")
    except AssertionError as e:
        print(f"  ✅ {name}: 断言触发 ✔  ({str(e)[:64]})")
    except Exception as e:
        FAILED.append(name); print(f"  ❌ {name}: 非断言异常 {type(e).__name__}: {e}")

def make_secure(name, port, peer_did_placeholder=False, call_ctx=None):
    st = AgentLinkState(name=name, port=port, did=f"did:agentlink:{name}")
    sec = SecureSessionManager(st, keypair=generate_keypair(name))
    st._call_context = call_ctx or {}
    return st, sec

# ─── 用例1: call_context 未 set 时 encrypt（静默降级场景）───
def case1():
    st, sec = make_secure("Eve", 18901)
    sec.e2ee_enabled = True; sec.cipher = True   # 逼 _peer_from_ctx 走断言路径
    expect_assert("用例1 call_context未set", sec._peer_from_ctx)

# ─── 用例2: peer_did 是占位符时 encrypt（AD不对称场景）───
def case2():
    st, sec = make_secure("Mallory", 18902,
        call_ctx={"enc_public_b64": _b64(generate_keypair("Carl").enc_public),
                  "sign_public_b64": _b64(generate_keypair("Carl").sign_public),
                  "caller_did": "did:wba:192.168.1.7-18790"})
    shared = compute_shared_secret(sec.kp.enc_private, _unb64(st._call_context["enc_public_b64"]))
    key, salt = derive_session_key(shared)
    sec.cipher = SessionCipher(key, salt, st.did, "did:wba:192.168.1.7-18790")
    sec.e2ee_enabled = True
    st.peer_did = "did:wba:192.168.1.7-18790"    # 占位符没被 ring 覆盖
    expect_assert("用例2 占位符DID→encrypt", lambda: sec.encrypt_payload("hello"))

# ─── 用例3: 加密会话收到明文帧（前缀不对称）───
async def case3():
    st, sec = make_secure("Trent", 18903,
        call_ctx={"enc_public_b64": _b64(generate_keypair("Ursula").enc_public),
                  "sign_public_b64": _b64(generate_keypair("Ursula").sign_public),
                  "caller_did": generate_keypair("Ursula").did})
    shared = compute_shared_secret(sec.kp.enc_private, _unb64(st._call_context["enc_public_b64"]))
    key, salt = derive_session_key(shared)
    sec.cipher = SessionCipher(key, salt, st.did, st._call_context["caller_did"])
    sec.e2ee_enabled = True
    try:
        await sec.on_data("明文帧没有前缀", 1, "text")
        FAILED.append("用例3"); print("  ❌ 用例3 前缀不对称: 没触发断言（失效！）")
    except AssertionError as e:
        print(f"  ✅ 用例3 前缀不对称→on_data: 断言触发 ✔  ({str(e)[:64]})")
    except Exception as e:
        FAILED.append("用例3"); print(f"  ❌ 用例3: 非断言异常 {type(e).__name__}: {e}")

async def main():
    print("🔒 AgentLink 断言有效性验证\n" + "="*52)
    case1(); case2(); await case3()
    print("="*52)
    if FAILED:
        print(f"❌ {len(FAILED)} 个断言失效: {FAILED}")
        return 1
    print("🎉 全部 3 个不变量断言有效，能抓住对应 bug！")
    return 0

sys.exit(asyncio.run(main()))
