"""
AgentLink Signal Client — 信令服务客户端
封装注册、发现、中继、离线消息、在线列表
"""
from __future__ import annotations
import asyncio, json, time, uuid
from typing import Optional, Callable

import httpx
import websockets


class SignalClient:
    """
    信令服务客户端
    
    用法:
      client = SignalClient(my_agent_state, my_secure_manager, "http://localhost:9765")
      await client.register()
      found = await client.find("did:agentlink:bob:xxxx")
    """

    def __init__(self, state, secure, signal_url: str):
        self.state = state
        self.secure = secure
        self.signal_http = signal_url
        self.signal_ws = signal_url.replace("http://", "ws://").replace("https://", "wss://")
        self._ws = None
        self._http = httpx.AsyncClient(timeout=10)
        self._incoming_handler: Optional[Callable] = None
        self._connected = False

    # ─── HTTP API ───

    async def register(self) -> bool:
        """向信令服务注册本 agent"""
        from agentlink.secure_session import get_signal_registration_payload
        payload = get_signal_registration_payload(self.secure, self.state, self.signal_http)
        try:
            resp = await self._http.post(f"{self.signal_http}/signal/register", json=payload)
            data = resp.json()
            print(f"  📡 {self.state.name}: 注册到信令服务 → {data.get('result', data)}")
            return data.get("result") == "ok"
        except Exception as e:
            print(f"  ⚠️ {self.state.name}: 注册失败: {e}")
            return False

    async def unregister(self):
        """注销"""
        try:
            await self._http.post(f"{self.signal_http}/signal/unregister",
                                  json={"did": self.secure.kp.did})
        except Exception:
            pass

    async def find(self, did: str) -> Optional[dict]:
        """查找 agent"""
        try:
            resp = await self._http.get(f"{self.signal_http}/signal/find/{did}")
            data = resp.json()
            if "error" in data:
                return None
            return data
        except Exception:
            return None

    async def find_by_name(self, name: str) -> Optional[dict]:
        """通过名字查找——列出在线列表后匹配"""
        agents = await self.list_online()
        for a in agents:
            if a.get("name") == name or a.get("did", "").endswith(f":{name}"):
                info = await self.find(a["did"])
                if info and info.get("status") != "not_found":
                    return info
        return None

    async def list_online(self) -> list[dict]:
        """列出所有在线 agent"""
        try:
            resp = await self._http.get(f"{self.signal_http}/signal/online")
            data = resp.json()
            return data.get("agents", [])
        except Exception:
            return []

    async def send_offline_msg(self, target_did: str, payload: str,
                                msg_type: str = "text") -> int:
        """发送离线消息"""
        try:
            resp = await self._http.post(f"{self.signal_http}/signal/offline_msg", json={
                "target_did": target_did,
                "sender_did": self.secure.kp.did,
                "type": msg_type,
                "payload": payload,
            })
            data = resp.json()
            return data.get("message_id", 0)
        except Exception:
            return 0

    async def get_offline_msgs(self) -> list[dict]:
        """获取本 agent 的离线消息"""
        try:
            resp = await self._http.get(f"{self.signal_http}/signal/offline_msg/{self.secure.kp.did}")
            data = resp.json()
            return data.get("messages", [])
        except Exception:
            return []

    async def get_status(self) -> dict:
        """查询信令服务状态"""
        try:
            resp = await self._http.get(f"{self.signal_http}/signal/status")
            return resp.json()
        except Exception:
            return {"error": "unreachable"}

    # ─── WebSocket 连接（实时双向通信）───

    async def connect_ws(self, handler: Optional[Callable] = None):
        """
        建立 WebSocket 连接到信令服务
        handler: 可选的消息处理函数，接收 (method, params) 参数
        """
        self._incoming_handler = handler
        try:
            self._ws = await websockets.connect(f"{self.signal_ws}/signal/ws")
            self._connected = True

            # 认证
            auth = self.secure.get_auth_payload()
            await self._ws.send(json.dumps({
                "method": "signal.auth",
                "params": {
                    "did": self.secure.kp.did,
                    "name": self.state.name,
                    "http_url": self.state.http_url,
                    "ws_url": self.state.ws_url,
                    "sign_public_b64": auth["sign_public_b64"],
                    "enc_public_b64": auth["enc_public_b64"],
                    "cert": auth.get("cert", {}),
                }
            }))
            resp = json.loads(await self._ws.recv())
            if "error" in resp:
                print(f"  ⚠️ {self.state.name}: WS 认证失败: {resp['error']}")
                self._connected = False
                return False

            print(f"  🔗 {self.state.name}: WS 连通信令服务 — 服务端 DID: {resp.get('params', {}).get('server_did', '?')}")

            # 检查是否有离线消息
            if resp.get("method") == "signal.offline_messages":
                msgs = resp.get("params", {}).get("messages", [])
                if msgs:
                    print(f"  📨 {self.state.name}: 收到 {len(msgs)} 条离线消息")

            # 启动监听协程
            asyncio.create_task(self._ws_listen())
            return True

        except Exception as e:
            print(f"  ⚠️ {self.state.name}: WS 连接失败: {e}")
            self._connected = False
            return False

    async def _ws_listen(self):
        """WS 监听循环"""
        try:
            async for raw in self._ws:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                method = data.get("method", "")
                params = data.get("params", {})

                if method == "signal.incoming":
                    # 收到中继消息
                    from_did = params.get("from_did", "")
                    payload = params.get("payload", {})
                    print(f"  📨 {self.state.name}: 收到中继消息 from {from_did}: {str(payload)[:60]}")

                    if self._incoming_handler:
                        await self._incoming_handler("incoming", {
                            "from_did": from_did,
                            "payload": payload,
                        })

                elif method == "signal.offline_messages":
                    msgs = params.get("messages", [])
                    print(f"  📨 {self.state.name}: 收到 {len(msgs)} 条离线消息")
                    if self._incoming_handler:
                        for m in msgs:
                            await self._incoming_handler("offline_msg", m)

                elif method == "signal.relay":
                    # 中继确认
                    pass

                elif "error" in data:
                    print(f"  ⚠️ {self.state.name}: WS 错误: {data['error']}")

        except websockets.exceptions.ConnectionClosed:
            self._connected = False
            print(f"  ⚠️ {self.state.name}: WS 断开")
        except Exception as e:
            self._connected = False
            print(f"  ⚠️ {self.state.name}: WS 监听异常: {e}")

    async def relay(self, target_did: str, payload: dict) -> bool:
        """通过信号服务中继消息到另一个 agent"""
        if not self._connected or not self._ws:
            print(f"  ⚠️ {self.state.name}: WS 未连接，无法中继")
            return False
        try:
            await self._ws.send(json.dumps({
                "method": "signal.relay",
                "params": {
                    "target_did": target_did,
                    "payload": payload,
                }
            }))
            return True
        except Exception as e:
            print(f"  ⚠️ {self.state.name}: 中继失败: {e}")
            return False

    async def signal_find(self, did: str) -> Optional[dict]:
        """通过 WS 查找"""
        if not self._connected or not self._ws:
            return await self.find(did)
        try:
            await self._ws.send(json.dumps({
                "method": "signal.find",
                "params": {"did": did}
            }))
            resp = json.loads(await asyncio.wait_for(self._ws.recv(), timeout=5))
            if resp.get("result") == "found":
                return resp.get("params", {})
            return None
        except Exception:
            return await self.find(did)

    def disconnect(self):
        """断开连接"""
        self._connected = False
        self._ws = None

    async def close(self):
        """清理"""
        self.disconnect()
        await self._http.aclose()
