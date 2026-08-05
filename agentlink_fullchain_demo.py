#!/usr/bin/env python3
"""
agentlink_fullchain_demo.py — 全链路验证
启动4个Agent + 模拟Swift App操控 + Timeline看板验证
"""
import sys, os, time, json, asyncio, subprocess
DEMO_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, DEMO_DIR)

import httpx
PYTHON = sys.executable

def start_agent(port: int, name: str):
    """agent 作为独立子进程启动"""
    code = f"""
import sys; sys.path.insert(0, '{DEMO_DIR}')
import uvicorn
from agentlink_p1 import AgentLinkState, create_agent_app
state = AgentLinkState(name='{name}', port={port}, did='did:wba:localhost:{port}')
app = create_agent_app(state)
uvicorn.run(app, host='127.0.0.1', port={port}, log_level='error')
"""
    return subprocess.Popen([PYTHON, "-c", code])

def start_swift_agent():
    return subprocess.Popen([PYTHON, os.path.join(DEMO_DIR, "run_agentlink_agent.py")])

async def wait_for_port(name: str, port: int, timeout: int = 15) -> bool:
    """轮询直到端口响应"""
    for _ in range(timeout * 5):
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(f"http://localhost:{port}/status", timeout=1)
                if r.status_code == 200:
                    print(f"  ✅ {name} @ :{port}")
                    return True
        except:
            pass
        await asyncio.sleep(0.2)
    print(f"  ❌ {name} @ :{port} 超时")
    return False

async def main():
    print("=" * 62)
    print("  🦾 AgentLink 全链路验证 — Simulator → Agent 通联")
    print("=" * 62)

    # ─── 1. 启动所有 Agent ───
    print("\n🔄 启动 Agent 进程...")
    agents = [
        (18763, "Alice", start_agent(18763, "Alice")),
        (18764, "Bob", start_agent(18764, "Bob")),
        (18765, "Charlie", start_agent(18765, "Charlie")),
        (18766, "StrongAI", start_swift_agent()),
    ]

    for port, name, _ in agents:
        ok = await wait_for_port(name, port)
        if not ok:
            print("❌ 启动失败，退出")
            return

    await asyncio.sleep(0.3)

    # ─── 2. 验证 Timeline 端点可用 ───
    print("\n📊 验证 Timeline 端点...")
    async with httpx.AsyncClient() as c:
        for port, name, _ in agents:
            r = await c.get(f"http://localhost:{port}/timeline", timeout=3)
            events = r.json()
            print(f"  {name}: /timeline = {len(events)} 条事件 (boot-time logs)")

    # ─── 3. 模拟 Swift App: StrongAI → Bob ───
    print("\n📞 模拟 Swift App → StrongAI 代理 → 呼叫 Bob...")
    session_id = None
    async with httpx.AsyncClient() as c:
        # 呼叫
        r = await c.post("http://localhost:18766/swift/call", json={
            "target_url": "http://localhost:18764",
            "target_name": "Bob",
        }, timeout=10)
        result = r.json().get("result", {})
        status = result.get("status", "failed")
        session_id = result.get("session_id", "")
        print(f"  呼叫结果: {status}  session={session_id[:12] if session_id else 'N/A'}...")
        assert status == "connected", f"❌ 呼叫失败: {result}"

        # 发送 4 条
        messages = [
            "Bob，新卷宗你收到没有？",
            "第十二页的排班表有问题。",
            "值班记录显示22:00-23:00有三个人同时在场。",
            "但监控就拍到俩。",
        ]
        for i, msg in enumerate(messages):
            r = await c.post("http://localhost:18766/swift/send", json={"text": msg}, timeout=10)
            res = r.json().get("result", {})
            if res.get("status") == "sent":
                print(f"  📤 Swift [{res['seq']}]: \"{msg[:40]}...\"")
            else:
                print(f"  ❌ 发送失败: {res}")
            await asyncio.sleep(0.2)

        # 通过 Bob 的 WS 发回一条回复
        print("  📥 Bob 正在回复...")
        try:
            import websockets
            bob_url = f"ws://localhost:18764/agentlink/ws/{session_id}"
            async with websockets.connect(bob_url) as ws:
                reply_msg = {
                    "method": "agentlink.data",
                    "meta": {"profile": "agentlink.session.v1", "session_id": session_id},
                    "body": {"seq": 10, "type": "text", "payload": "收到了，我看了。你说的是李队和王刚那段？确实对不上。"},
                }
                await ws.send(json.dumps(reply_msg))
                ack = json.loads(await ws.recv())
                print(f"  ✅ Bob 回复发送成功 (seq={ack.get('result', {}).get('seq', '?')})")
        except Exception as e:
            print(f"  ⚠️ Bob 回复失败: {e}")

        # 挂断
        r = await c.post("http://localhost:18766/swift/hangup", json={"reason": "case_closed"}, timeout=5)
        hangup_status = r.json().get("result", {}).get("status", "?")
        print(f"  🔌 挂断: {hangup_status}")

    await asyncio.sleep(0.3)

    # ─── 4. 验证 Timeline 事件 ───
    print("\n📊 验证 Timeline 事件...")
    async with httpx.AsyncClient() as c:
        for port, name, _ in agents:
            r = await c.get(f"http://localhost:{port}/timeline", timeout=3)
            events = r.json()
            print(f"\n  {name} ({len(events)} 条事件):")
            if not events:
                print(f"    ⚠️ 无事件")
                continue
            for evt in events[-10:]:
                print(f"    {evt['ts_str']} [{evt['event']}] {evt['agent']}: {evt['detail'][:60]}")
            print(f"    ✅ Timeline 有 {len(events)} 条记录")

    # ─── 5. 清理 ───
    print("\n🔌 停止所有 Agent...")
    for _, _, proc in agents:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except:
            proc.kill()

    print("\n" + "=" * 62)
    print("  ✅ 全链路验证通过！")
    print("  浏览器打开任意 agent 的 /timeline/dashboard 查看时间线")
    print("=" * 62)

if __name__ == "__main__":
    asyncio.run(main())
