// Note: this implementation is only compatible with kicq server (kicq.ru or 195.66.114.37) use the file AT YOUR OWN RISK!

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Foundation;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Windows.UI.Popups;
using System.Collections.ObjectModel;
using Windows.UI.Core;

namespace kicquwp
{
    public class OscarProtocol : IDisposable
    {
        private StreamSocket _socket;
        private DataWriter _writer;
        private DataReader _reader;
        private byte _sequenceNumber;
        private readonly string _uin;
        private readonly string _password;
        private ushort _flapSequenceNumber = 0;
        // _readLock убран — синхронизация теперь через _flapQueueLock
        // в сыром движке чтения (см. StartRawReceiveLoop и далее),
        // обязательном для совместной работы с ControlChannelTrigger.
        // SNAC service handlers
        private CancellationTokenSource _receiveCts;
        private ObservableCollection<Contact> contacts;
        private Dictionary<string, List<string[]>> _pendingMessages =
        new Dictionary<string, List<string[]>>();
        public event Action ContactStatusChanged;
        public event Action<string, string> ContactRenamed; // uin, newName
        public event Action<string> ContactRemoved; // uin
        public event Action<Contact> TemporaryContactAdded;
        public event Action<string, ushort> TypingNotificationReceived; // uin, type
        public event Action<UserBasicInfo> OwnInfoReceived;
        private static OscarProtocol _instance;
        public event Action ConnectionLost;
        public string LastAuthError { get; private set; }
        public Action<string> StatusUpdater { get; set; }
        public event Action<string, string> IncomingMessage;
        private Dictionary<ushort, SsiGroup> _ssiGroups = new Dictionary<ushort, SsiGroup>();

        // Множество UIN-ов, для которых мы УЖЕ отправили запрос capabilities
        // (SNAC 02,05 type=0x0004) после подключения. Без этого при загрузке
        // списка из 200 контактов мы бы отправили 200 SNAC(02,05) подряд и
        // словили rate limit от сервера.
        //
        // Запрос отправляется ВСЕГДА после SNAC(03,0B), даже если в самом
        // 0x0B уже пришли capabilities — потому что на kicq (iserverd)
        // QIP-режим контакта там не передаётся, и единственный способ
        // узнать, что у контакта сейчас Evil/Home/Lunch — это явный
        // запрос capabilities через SNAC(02,05) type=0x0004.
        private readonly HashSet<string> _capabilitiesRequested
            = new HashSet<string>();
        public event Action<List<SearchResult>, bool> SearchResultReceived;
        public event Action<UserFullInfo> UserInfoReceived;
        private ushort _snacRequestId = 1;
        public event Action<string> DisconnectedByServer;
        private Action<ushort> _ssiAckHandler;

        private static readonly HashSet<ushort> IcqSupportedFamilies = new HashSet<ushort>
{
    0x0001, // Generic
    0x0002, // Location services
    0x0003, // Buddy List management
    0x0004, // Messaging (ICBM)
    0x0009, // Privacy
    0x000B, // Usage stats
    0x0010, // Server-stored buddy icons
    0x0013, // Server Side Information (SSI)
    0x0015, // ICQ-specific extensions
    0x0017  // Authorization/registration
};
        private Task _;
        private ushort _icbmMaxSize;

        public ushort GetNextRequestID()
        {
            return _snacRequestId++;
        }

        private void OnConnectionLost(string reason)
        {
            Debug.WriteLine("[OscarProtocol] Connection lost: " + reason);
            try { _receiveCts?.Cancel(); } catch { }
            if (ConnectionLost != null) ConnectionLost();
        }

        public bool IsConnected
        {
            get { return _socket != null && _reader != null && _writer != null; }
        }

        public static OscarProtocol Instance
        {
            get { return _instance; }
            set { _instance = value; }
        }

        public string UIN { get; private set; }
        public CoreDispatcher _dispatcher { get; private set; }

        public OscarProtocol(string uin, string password, CoreDispatcher dispatcher)
        {
            if (string.IsNullOrWhiteSpace(uin)) throw new ArgumentNullException(nameof(uin));
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));

            UIN = uin;
            _uin = uin;
            _password = password;
            _dispatcher = dispatcher;

            Debug.WriteLine($"[OscarProtocol] Created with UIN: {_uin}");
        }

        public class SsiGroup
        {
            public ushort GroupId { get; set; }
            public ushort ItemId { get; set; }
            public string Name { get; set; }
            public List<ushort> MemberIds { get; set; }

            public SsiGroup()
            {
                MemberIds = new List<ushort>();
            }
        }

        internal string GetContactStatus(string uin)
        {
            throw new NotImplementedException();
        }

        private async Task ConnectAsync()
        {
            _socket = new StreamSocket();
            var hostName = new HostName("195.66.114.37");

            // Инициализируем CCT ДО подключения
            var trigger = await ControlChannelService.Instance.InitializeAsync();
            if (trigger != null)
            {
                bool assigned = ControlChannelService.Instance.AssignSocket(_socket);
                Debug.WriteLine("[ConnectAsync] CCT assigned: " + assigned);
            }

            await _socket.ConnectAsync(hostName, "5190");

            if (trigger != null)
            {
                try
                {
                    bool pushEnabled = ControlChannelService.Instance.WaitForPushEnabled();
                    Debug.WriteLine("[ConnectAsync] Push enabled: " + pushEnabled);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("[ConnectAsync] WaitForPushEnabled error: " + ex.Message);
                }
            }

            _writer = new DataWriter(_socket.OutputStream);
            _reader = new DataReader(_socket.InputStream)
            {
                InputStreamOptions = InputStreamOptions.Partial,
                ByteOrder = ByteOrder.BigEndian
            };
            StartRawReceiveLoop();
        }

        private byte[] BuildSnacPayload(ushort family, ushort subtype, ushort flags, uint requestId, List<byte[]> tlvs)
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write((ushort)family);      // SNAC Family
                writer.Write((ushort)subtype);     // SNAC Subtype
                writer.Write((ushort)flags);       // Flags
                writer.Write((uint)requestId);     // Request ID

                foreach (var tlv in tlvs)
                {
                    writer.Write(tlv);
                }

                return ms.ToArray();
            }
        }

        internal Task<DateTime> GetLastOnlineTimeAsync(string uin)
        {
            throw new NotImplementedException();
        }

        private byte[] BuildTlv(ushort type, byte[] value)
        {
            using (var ms = new MemoryStream())
            {
                byte[] typeBytes = BitConverter.GetBytes(type);
                byte[] lengthBytes = BitConverter.GetBytes((ushort)value.Length);

                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(typeBytes);
                    Array.Reverse(lengthBytes);
                }

                ms.Write(typeBytes, 0, 2);
                ms.Write(lengthBytes, 0, 2);
                ms.Write(value, 0, value.Length);

                return ms.ToArray();
            }
        }

        public async Task<bool> AuthenticateAsync(uint statusCode)
        {
            Debug.WriteLine("[Auth] Starting authentication...");

            try
            {
                await ConnectAsync();

                await SendFlapAsync(0x01, new byte[] { 0x00, 0x00, 0x00, 0x01 });

                var response = await ReceiveFlapWithTimeout(TimeSpan.FromSeconds(5));
                if (response == null)
                {
                    Debug.WriteLine("[Auth] No response from server");
                    return false;
                }

                Debug.WriteLine($"[FLAP] Type: {response.Channel}, Length: {response.Data.Length}, Data: {BitConverter.ToString(response.Data)}");

                if (response.Channel != 0x01)
                {
                    Debug.WriteLine("[Auth] Invalid FLAP response type");
                    return false;
                }

                if (response.Data.Length == 4 &&
                    response.Data[0] == 0x00 &&
                    response.Data[1] == 0x00 &&
                    response.Data[2] == 0x00 &&
                    response.Data[3] == 0x01)
                {
                    Debug.WriteLine("[Auth] Using DirectAuth method");
                    return await DirectAuth(statusCode);
                }

                if (response.Data.Length > 0)
                {
                    var tlvs = ParseTlvs(response.Data);
                    TLV challengeTlv;
                    if (tlvs.TryGetValue(0x0006, out challengeTlv))
                    {
                        Debug.WriteLine("[Auth] Using ChallengeAuth method");
                        return await SendLoginWithChallenge(challengeTlv.Value);
                    }
                }

                Debug.WriteLine("[Auth] No valid auth method detected");
                return false;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[Auth ERROR] " + ex.Message);

                // Определяем тип ошибки по HRESULT
                if (ex.Message.Contains("0x8007274C") ||
                    ex.Message.Contains("did not properly respond") ||
                    ex.Message.Contains("host has failed to respond"))
                {
                    LastAuthError = "Сервер не отвечает. Проверьте подключение к интернету.";
                }
                else if (ex.Message.Contains("0x8007274D") ||
                         ex.Message.Contains("connection was forcibly closed") ||
                         ex.Message.Contains("No connection could be made"))
                {
                    LastAuthError = "Не удалось подключиться к серверу. Сервер может быть недоступен.";
                }
                else if (ex.Message.Contains("0x80072AF9") ||
                         ex.Message.Contains("internet") ||
                         ex.Message.Contains("0x80072751"))
                {
                    LastAuthError = "Нет подключения к интернету.";
                }
                else
                {
                    LastAuthError = "Ошибка подключения: " + ex.Message;
                }

                return false;
            }
        }

        // Jasmine createXORLogin: гибридный формат (НЕ-TLV поля + TLV блоки)
        // Клиентская строка ICQ 2000b, версии 4.65.1.3281, distribution 85
        private const string CLIENT_STRING = "ICQ Inc. - Product of ICQ (TM).2000b.4.65.1.3281.85";

        public async Task<bool> DirectAuth(uint statusCode)
        {
            try
            {
                byte[] clientBytes = Encoding.ASCII.GetBytes(CLIENT_STRING);
                byte[] xorPass = RoastPassword(_password);
                byte[] uinBytes = Encoding.ASCII.GetBytes(_uin);

                using (var ms = new MemoryStream())
                {
                    // ═══ Гибридный формат: голые поля + TLV (как в Jasmine createXORLogin) ═══
                    WriteU32BE(ms, 0x00000001);                      // DWord: 1
                    WriteU16BE(ms, 0x0001);                          // WORD: login type = 1
                    WriteU16BE(ms, (ushort)uinBytes.Length);         // PreLengthString: UIN
                    ms.Write(uinBytes, 0, uinBytes.Length);
                    WriteU16BE(ms, 0x0002);                          // WORD: password type = 2 (XOR)
                    WriteU16BE(ms, (ushort)xorPass.Length);          // WORD: xor len
                    ms.Write(xorPass, 0, xorPass.Length);

                    // TLV 0x03 — Client string
                    WriteTlvBE(ms, 0x0003, clientBytes);
                    // TLV 0x16 — {0x01,0x0A}
                    WriteTlvBE(ms, 0x0016, new byte[] { 0x01, 0x0A });
                    // TLV 0x17 — Major = 4
                    WriteTlvBE(ms, 0x0017, new byte[] { 0x00, 0x04 });
                    // TLV 0x18 — Minor = 65
                    WriteTlvBE(ms, 0x0018, new byte[] { 0x00, 0x41 });
                    // TLV 0x19 — Lesser = 1
                    WriteTlvBE(ms, 0x0019, new byte[] { 0x00, 0x01 });
                    // TLV 0x1A — Build = 3281
                    WriteTlvBE(ms, 0x001A, new byte[] { 0x0C, 0xD1 });
                    // TLV 0x14 — Distribution = 85
                    WriteTlvDWordBE(ms, 0x0014, 0x00000055);
                    // TLV 0x0F — Language "en"
                    WriteTlvBE(ms, 0x000F, new byte[] { (byte)'e', (byte)'n' });
                    // TLV 0x0E — Country "us"
                    WriteTlvBE(ms, 0x000E, new byte[] { (byte)'u', (byte)'s' });

                    byte[] flapData = ms.ToArray();
                    Debug.WriteLine($"[DirectAuth] XOR login FLAP ch=0x01, {flapData.Length} bytes");
                    StatusUpdater?.Invoke("Отправляю login request (XOR)...");
                    await SendFlapAsync(0x01, flapData);
                }

                Debug.WriteLine("[DirectAuth] Waiting for login response...");
                var flap = await ReceiveFlapWithTimeout(TimeSpan.FromSeconds(10));
                if (flap?.Channel == 0x04)
                {
                    string authError = ParseAuthError(flap.Data);
                    if (authError != null) { LastAuthError = authError; return false; }
                    return await HandleBosRedirectAsync(flap.Data, 0x00000000);
                }
                if (flap == null) { LastAuthError = "Сервер не ответил."; return false; }
                LastAuthError = "Неожиданный ответ от сервера.";
                return false;
            }
            catch (Exception ex) { Debug.WriteLine($"[DirectAuth ERROR] {ex.Message}"); return false; }
        }

        public async Task<string> RegisterNewAccountAsync(string password)
        {
            Debug.WriteLine("[Register] Starting registration...");

            // Генерируем случайный cookie
            var rng = new Random();
            uint cookie = (uint)rng.Next();

            StreamSocket regSocket = null;
            DataWriter regWriter = null;
            DataReader regReader = null;

            try
            {
                // Подключаемся к серверу авторизации
                regSocket = new StreamSocket();
                await regSocket.ConnectAsync(
                    new Windows.Networking.HostName("195.66.114.37"), "5190");

                regWriter = new DataWriter(regSocket.OutputStream);
                regReader = new DataReader(regSocket.InputStream)
                {
                    InputStreamOptions = InputStreamOptions.Partial
                };

                // Читаем приветственный FLAP channel 0x01
                uint hLen = await regReader.LoadAsync(6);
                if (hLen < 6) throw new Exception("Нет ответа от сервера");
                byte[] hello = new byte[6];
                regReader.ReadBytes(hello);
                ushort hDataLen = (ushort)((hello[4] << 8) | hello[5]);
                if (hDataLen > 0)
                {
                    await regReader.LoadAsync(hDataLen);
                    byte[] hData = new byte[hDataLen];
                    regReader.ReadBytes(hData);
                }

                // Отправляем FLAP channel 0x01 (hello)
                byte[] helloFlap = new byte[] { 0x2A, 0x01, 0x00, 0x01, 0x00, 0x04,
                                         0x00, 0x00, 0x00, 0x01 };
                regWriter.WriteBytes(helloFlap);
                await regWriter.StoreAsync();

                // Строим SNAC(17,04) — запрос регистрации
                byte[] passBytes = System.Text.Encoding.UTF8.GetBytes(password + "\0");
                ushort passLen = (ushort)passBytes.Length;
                ushort unknown = (ushort)rng.Next(0xFFFF);

                using (var ms = new System.IO.MemoryStream())
                {
                    // TLV(0x0001) header
                    WriteU16BE(ms, 0x0001);

                    // Считаем длину тела TLV
                    int bodyLen = 4 + 2 + 2 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 +
                                  2 + passBytes.Length + 4 + 4 + 2;
                    WriteU16BE(ms, (ushort)bodyLen);

                    // Тело TLV
                    WriteU32LE(ms, 0x00000000);          // zeros
                    WriteU16LE(ms, 0x0028);              // subcmd
                    WriteU16LE(ms, 0x0003);              // sequence
                    WriteU32LE(ms, 0x00000000);          // zeros
                    WriteU32LE(ms, 0x00000000);          // zeros
                    WriteU32LE(ms, cookie);              // registration cookie
                    WriteU32LE(ms, cookie);              // registration cookie (same)
                    WriteU32LE(ms, 0x00000000);          // zeros
                    WriteU32LE(ms, 0x00000000);          // zeros
                    WriteU32LE(ms, 0x00000000);          // zeros
                    WriteU32LE(ms, 0x00000000);          // zeros
                    WriteU16LE(ms, passLen);             // password len (LE)
                    ms.Write(passBytes, 0, passBytes.Length); // password asciiz
                    WriteU32LE(ms, cookie);              // registration cookie (same)
                    WriteU32LE(ms, 0x00000000);          // zeros
                    WriteU16LE(ms, unknown);             // unknown random

                    byte[] snacBody = ms.ToArray();

                    // Строим SNAC(17,04)
                    using (var snacMs = new System.IO.MemoryStream())
                    {
                        WriteU16BE(snacMs, 0x0017); // family
                        WriteU16BE(snacMs, 0x0004); // subtype
                        WriteU16BE(snacMs, 0x0000); // flags
                        WriteU32BE(snacMs, 0x00000000); // request id
                        snacMs.Write(snacBody, 0, snacBody.Length);

                        byte[] snacData = snacMs.ToArray();

                        // FLAP header
                        byte[] flap = new byte[6 + snacData.Length];
                        flap[0] = 0x2A;
                        flap[1] = 0x02;
                        flap[2] = 0x00;
                        flap[3] = 0x02; // seq
                        flap[4] = (byte)(snacData.Length >> 8);
                        flap[5] = (byte)(snacData.Length & 0xFF);
                        Array.Copy(snacData, 0, flap, 6, snacData.Length);

                        regWriter.WriteBytes(flap);
                        await regWriter.StoreAsync();
                        Debug.WriteLine("[Register] Sent SNAC(17,04)");
                    }
                }

                // Читаем ответ — SNAC(17,05) или SNAC(17,01)
                var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
                while (DateTime.UtcNow < deadline)
                {
                    uint rHLen = await regReader.LoadAsync(6);
                    if (rHLen < 6) break;

                    byte[] rHeader = new byte[6];
                    regReader.ReadBytes(rHeader);

                    ushort rDataLen = (ushort)((rHeader[4] << 8) | rHeader[5]);
                    if (rDataLen == 0) continue;

                    uint rDLen = await regReader.LoadAsync(rDataLen);
                    if (rDLen < rDataLen) break;

                    byte[] rData = new byte[rDataLen];
                    regReader.ReadBytes(rData);

                    if (rData.Length < 4) continue;

                    ushort family = (ushort)((rData[0] << 8) | rData[1]);
                    ushort subtype = (ushort)((rData[2] << 8) | rData[3]);

                    Debug.WriteLine("[Register] Got SNAC(" + family.ToString("X2") +
                                    "," + subtype.ToString("X2") + ")");

                    if (family == 0x0017 && subtype == 0x0005)
                    {
                        // SNAC(17,05) — успех, парсим новый UIN
                        // Структура: 10 байт SNAC header + TLV(0x0001)
                        // Внутри TLV: 2(len-2) + 4(zeros) + 2(subcmd) + 2(seq) +
                        //             4(port) + 4(ip) + 4(unknown) + 4(cookie) +
                        //             16(zeros) + 4(new_uin LE) + ...
                        int offset = 10; // пропускаем SNAC header (4 family+sub + 2 flags + 4 reqid)

                        // TLV(0x0001)
                        if (offset + 4 > rData.Length) break;
                        offset += 4; // пропускаем TLV type и length

                        // Внутри TLV — LE структура
                        offset += 2; // len-2
                        offset += 4; // zeros
                        offset += 2; // subcmd 0x2D
                        offset += 2; // sequence
                        offset += 4; // client tcp port
                        offset += 4; // client ip
                        offset += 4; // unknown 0x00000004
                        offset += 4; // registration cookie
                        offset += 16; // zeros (4 dwords)

                        if (offset + 4 > rData.Length) break;

                        // New UIN в LE
                        uint newUin = (uint)(rData[offset] |
                                            (rData[offset + 1] << 8) |
                                            (rData[offset + 2] << 16) |
                                            (rData[offset + 3] << 24));

                        Debug.WriteLine("[Register] New UIN: " + newUin);
                        return newUin.ToString();
                    }
                    else if (family == 0x0017 && subtype == 0x0001)
                    {
                        // SNAC(17,01) — ошибка
                        if (rData.Length >= 12)
                        {
                            int eoff = 10;
                            ushort errCode = (ushort)((rData[eoff] << 8) | rData[eoff + 1]);
                            string errMsg = GetAuthErrorText(errCode);
                            Debug.WriteLine("[Register] Error: " + errMsg);
                            throw new Exception(errMsg);
                        }
                        throw new Exception("Ошибка регистрации");
                    }
                }

                throw new Exception("Сервер не ответил на запрос регистрации");
            }
            finally
            {
                try { regWriter?.DetachStream(); regWriter?.Dispose(); } catch { }
                try { regReader?.DetachStream(); regReader?.Dispose(); } catch { }
                try { regSocket?.Dispose(); } catch { }
            }
        }


        private string GetAuthErrorText(ushort code)
        {
            switch (code)
            {
                case 0x0001: return "Неверный логин или пароль";
                case 0x0002: return "Сервис временно недоступен";
                case 0x0003: return "Ошибка сервера";
                case 0x0010: return "Сервис временно отключён";
                case 0x0011: return "Аккаунт приостановлен";
                case 0x0016: return "Превышено количество подключений с этого IP";
                case 0x0018: return "Превышен лимит запросов. Попробуйте позже";
                case 0x001D: return "Превышен лимит. Попробуйте позже";
                case 0x001E: return "Не удаётся подключиться. Попробуйте позже";
                default: return "Ошибка 0x" + code.ToString("X4");
            }
        }


        private string ParseAuthError(byte[] data)
        {
            try
            {
                int offset = 0;
                ushort errorCode = 0;
                bool hasError = false;

                while (offset + 4 <= data.Length)
                {
                    ushort tlvType = ReadU16(data, ref offset);
                    ushort tlvLen = ReadU16(data, ref offset);
                    if (offset + tlvLen > data.Length) break;

                    if (tlvType == 0x0008 && tlvLen >= 2)
                    {
                        errorCode = ReadU16(data, ref offset);
                        hasError = true;
                    }
                    else if (tlvType == 0x0005)
                    {
                        // Это BOS cookie — не ошибка
                        return null;
                    }
                    else
                    {
                        offset += tlvLen;
                    }
                }

                if (!hasError) return null;

                switch (errorCode)
                {
                    case 0x0001: return "Неверный логин или пароль.";
                    case 0x0002: return "Сервис временно недоступен. Попробуйте позже.";
                    case 0x0003: return "Произошла ошибка. Попробуйте позже.";
                    case 0x0004: return "Неверный логин или пароль. Попробуйте снова.";
                    case 0x0005: return "Неверный логин или пароль. Попробуйте снова.";
                    case 0x0006: return "Ошибка клиента при авторизации.";
                    case 0x0007: return "Аккаунт не существует.";
                    case 0x0008: return "Аккаунт удалён.";
                    case 0x0009: return "Срок действия аккаунта истёк.";
                    case 0x000A: return "Нет доступа к базе данных.";
                    case 0x000B: return "Нет доступа к серверу.";
                    case 0x000F: return "Внутренняя ошибка сервера.";
                    case 0x0010: return "Сервис временно отключён. Попробуйте позже.";
                    case 0x0011: return "Аккаунт приостановлен.";
                    case 0x0016: return "Превышено количество подключений с этого IP.";
                    case 0x0018: return "Превышен лимит запросов. Попробуйте через несколько минут.";
                    case 0x001D: return "Превышен лимит запросов. Попробуйте через несколько минут.";
                    case 0x001E: return "Не удаётся подключиться к сети. Попробуйте через несколько минут.";
                    default: return "Ошибка авторизации (код 0x" + errorCode.ToString("X4") + ").";
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[ParseAuthError] " + ex.Message);
                return null;
            }
        }


        private async Task<bool> SendLoginWithChallenge(byte[] challenge) //(нерабочий) TODO: безопасный логин
        {
            try
            {
                Debug.WriteLine($"[ChallengeAuth] Challenge: {BitConverter.ToString(challenge)}");

                byte[] pwBytes = Encoding.UTF8.GetBytes(_password);
                byte[] toHash = new byte[challenge.Length + 1 + pwBytes.Length];

                System.Buffer.BlockCopy(challenge, 0, toHash, 0, challenge.Length);
                toHash[challenge.Length] = 0x00;
                System.Buffer.BlockCopy(pwBytes, 0, toHash, challenge.Length + 1, pwBytes.Length);

                var alg = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);
                byte[] hash = alg.HashData(CryptographicBuffer.CreateFromByteArray(toHash)).ToArray();
                Debug.WriteLine($"[ChallengeAuth] MD5 Hash: {BitConverter.ToString(hash)}");

                var tlvs = new List<TLV>
                {
                    new TLV(0x0001, Encoding.UTF8.GetBytes(_uin)),
                    new TLV(0x0002, hash),
                    new TLV(0x0003, new byte[] {0x00, 0x00, 0x00, 0x01}),
                    new TLV(0x0016, new byte[] {0x01, 0x0A}),
                    new TLV(0x0017, new byte[] {0x00, 0x14}),
                    new TLV(0x0018, new byte[] {0x00, 0x34}),
                    new TLV(0x0019, new byte[] {0x00, 0x00}),
                    new TLV(0x001A, new byte[] {0x0B, 0xB8}),
                    new TLV(0x0014, new byte[] {0x00, 0x00, 0x04, 0x3D}),
                    new TLV(0x000F, Encoding.UTF8.GetBytes("en")),
                    new TLV(0x000E, Encoding.UTF8.GetBytes("us")),
                    new TLV(0x0002, Encoding.UTF8.GetBytes("QIP user"))
                };

                await SendTlvLogin(tlvs);
                await Task.Delay(300);

                var response = await ReceiveFlapWithTimeout(TimeSpan.FromSeconds(5));
                return response != null && response.Channel == 0x02;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ChallengeAuth ERROR] {ex.Message}");
                return false;
            }
        }

        private async Task SendTlvLogin(List<TLV> tlvs)
        {
            byte[] tlvPayload = BuildTlvPayload(tlvs);
            Debug.WriteLine("[SendTlvLogin] TLV Payload: " + BitConverter.ToString(tlvPayload));

            byte[] flap = BuildFlapFrame(0x01, tlvPayload);
            Debug.WriteLine("[SendTlvLogin] Full FLAP Frame: " + BitConverter.ToString(flap));

            try
            {
                _writer.WriteBytes(flap);
                await _writer.StoreAsync();
                Debug.WriteLine("[SendTlvLogin] Frame sent successfully (" + flap.Length + " bytes)");

                await Task.Delay(300);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[SendTlvLogin ERROR] " + ex.Message);
                throw;
            }
        }

        private byte[] BuildTlvPayload(List<TLV> tlvs)
        {
            using (var ms = new MemoryStream())
            {
                foreach (var tlv in tlvs)
                {
                    byte[] typeBytes = BitConverter.GetBytes((ushort)tlv.Type);
                    byte[] lengthBytes = BitConverter.GetBytes((ushort)tlv.Value.Length);

                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(typeBytes);
                        Array.Reverse(lengthBytes);
                    }

                    ms.Write(typeBytes, 0, 2);
                    ms.Write(lengthBytes, 0, 2);
                    ms.Write(tlv.Value, 0, tlv.Value.Length);
                }

                return ms.ToArray();
            }
        }

        // Jasmine ROAST_CHARS — циклический XOR для пароля (ASCII!)
        private static readonly byte[] ROAST_CHARS = {
            0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92,
            0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C
        };

        private byte[] RoastPassword(string password)
        {
            byte[] input = Encoding.ASCII.GetBytes(password);  // Jasmine: getBytes("ASCII")
            byte[] roasted = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                roasted[i] = (byte)(input[i] ^ ROAST_CHARS[i % ROAST_CHARS.Length]);
            return roasted;
        }



        private byte[] BuildFlapFrame(byte channel, byte[] data)
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0x2A);
                ms.WriteByte(channel);
                ms.WriteByte(0x00);
                ms.WriteByte(_sequenceNumber++);
                ms.WriteByte((byte)(data.Length >> 8));
                ms.WriteByte((byte)(data.Length & 0xFF));
                ms.Write(data, 0, data.Length);
                return ms.ToArray();
            }
        }

        // TLV write helpers (BE)
        private void WriteTlvBE(MemoryStream ms, ushort type, byte[] value)
        {
            WriteU16BE(ms, type);
            WriteU16BE(ms, (ushort)value.Length);
            ms.Write(value, 0, value.Length);
        }
        private void WriteTlvDWordBE(MemoryStream ms, ushort type, uint value)
        {
            WriteU16BE(ms, type); WriteU16BE(ms, 4);
            WriteU32BE(ms, value);
        }

        private async Task SendFlapAsync(byte channel, byte[] data)
        {
            try
            {
                if (_writer == null) throw new Exception("Writer is null");
                if (data == null) data = new byte[0];
                _flapSequenceNumber++;

                byte[] packet = new byte[6 + data.Length];
                packet[0] = 0x2A;
                packet[1] = channel;
                packet[2] = (byte)(_flapSequenceNumber >> 8);
                packet[3] = (byte)(_flapSequenceNumber & 0xFF);
                packet[4] = (byte)(data.Length >> 8);
                packet[5] = (byte)(data.Length & 0xFF);
                Array.Copy(data, 0, packet, 6, data.Length);

                _writer.WriteBytes(packet);
                await _writer.StoreAsync();

                Debug.WriteLine("[SendFlap] Channel: 0x" + channel.ToString("X2") +
                                ", Seq: " + _flapSequenceNumber +
                                ", Length: " + data.Length);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[SendFlap ERROR] " + ex.Message);
                FailReader(ex); // единая точка обнаружения обрыва
                throw;
            }
        }



        private ushort[] ParseSupportedFamilies(byte[] data)
        {
            int count = (data.Length - 10) / 2;
            ushort[] families = new ushort[count];
            for (int i = 0; i < count; i++)
            {
                families[i] = (ushort)((data[10 + i * 2] << 8) | data[10 + i * 2 + 1]);
            }
            return families;
        }

        private async Task SendServiceVersionsRequestAsync(ushort[] supportedFamilies)
        {
            Debug.WriteLine("[Init] Building Service Versions Request...");

            if (supportedFamilies == null || supportedFamilies.Length == 0)
            {
                Debug.WriteLine("[Init ERROR] Нет доступных семейств от сервера.");
                return;
            }

            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                int count = 0;

                foreach (var family in supportedFamilies)
                {
                    if (!IcqSupportedFamilies.Contains(family))
                    {
                        Debug.WriteLine($"[Init] Пропущено семейство 0x{family:X4} (не поддерживается ICQ)");
                        continue;
                    }

                    ushort version = GetFamilyVersion(family);
                    writer.Write(SwapUInt16(family));
                    writer.Write(SwapUInt16(version));

                    Debug.WriteLine($"[Init] Семейство 0x{family:X4}, версия 0x{version:X4}");
                    count++;
                }

                if (count == 0)
                {
                    Debug.WriteLine("[Init ERROR] Нет ICQ-совместимых семейств для отправки.");
                    return;
                }

                byte[] payload = ms.ToArray();
                Debug.WriteLine($"[Init] Service version payload: {BitConverter.ToString(payload)}");

                StatusUpdater?.Invoke("Отправляем запрос версий сервисов...");

                ushort requestId = GetNextRequestID();
                await SendSnacAsync(0x01, 0x17, 0x0000, requestId, payload);

                Debug.WriteLine("[Init] Sent SNAC 0x01/0x17 (Service Versions Request)");
            }
        }




        private ushort GetFamilyVersion(ushort family)
        {
            switch (family)
            {
                case 0x0001: return 0x0001; // Generic service
                case 0x0002: return 0x0001; // Location
                case 0x0003: return 0x0001; // Buddy list
                case 0x0004: return 0x0001; // Messaging
                case 0x0006: return 0x0001; // Invitation
                case 0x0009: return 0x0001; // Privacy
                case 0x000B: return 0x0001; // Stats
                case 0x000C: return 0x0001; // Translation
                case 0x0013: return 0x0001; // SSI
                case 0x0015: return 0x0001; // ICQ extensions
                default: return 0x0001;
            }
        }







        private ushort SwapUInt16(ushort value)
        {
            return (ushort)((value >> 8) | (value << 8));
        }

        public async Task SendSnacAsync(ushort family, ushort subtype, ushort flags, uint requestId, byte[] data)
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write(SwapUInt16(family));       // SNAC family
                writer.Write(SwapUInt16(subtype));      // SNAC subtype
                writer.Write(SwapUInt16(flags));        // SNAC flags
                writer.Write(SwapUInt32(requestId));    // SNAC request ID (исправлено)

                if (data != null)
                    writer.Write(data);

                byte[] snacPayload = ms.ToArray();

                Debug.WriteLine($"[SendSnac] SNAC 0x{family:X4}/0x{subtype:X4}, RequestID=0x{requestId:X4}");
                Debug.WriteLine("[SendSnac] Payload: " + BitConverter.ToString(snacPayload));

                await SendFlapAsync(0x02, snacPayload); // Channel 0x02
            }
        }




        // Jasmine createClientReady: DWord family+ver + DWord subcode 0x0110140F
        private const uint CLIENT_READY_SUBCODE = 0x0110140F;
        private static readonly uint[] CLIENT_FAMILIES_DWORDS = {
            0x00220001, 0x00010004, 0x00130004, 0x00020001,
            0x00030001, 0x00150001, 0x00040001, 0x00060001,
            0x00090001, 0x000A0001, 0x000B0001
        };

        private async Task SendClientReadyAsync()
        {
            using (var ms = new MemoryStream())
            {
                foreach (var fv in CLIENT_FAMILIES_DWORDS)
                {
                    WriteU32BE(ms, fv);                   // family + version (DWord)
                    WriteU32BE(ms, CLIENT_READY_SUBCODE);  // 0x0110140F
                }
                await SendSnacAsync(0x01, 0x02, 0x0000, GetNextRequestID(), ms.ToArray());
                Debug.WriteLine("[ClientReady] SNAC(01,02) Jasmine format");
            }
        }



        private async Task WaitForServerFamiliesAsync()
        {
            Debug.WriteLine("[BOS] Waiting for SNAC 0x0001/0x0003 from server...");
            StatusUpdater?.Invoke("Ждем список сервисов...");
            while (true)
            {
                var flap = await ReceiveFlapWithTimeout(TimeSpan.FromSeconds(5));
                if (flap == null || flap.Channel != 0x02 || flap.Data.Length < 10)
                {
                    Debug.WriteLine("[BOS] Invalid or empty FLAP");
                    continue;
                }

                ushort family = (ushort)((flap.Data[0] << 8) | flap.Data[1]);
                ushort subtype = (ushort)((flap.Data[2] << 8) | flap.Data[3]);

                if (family == 0x0001 && subtype == 0x0003)
                {
                    StatusUpdater?.Invoke("Получили список сервисов...");
                    Debug.WriteLine("[BOS] Received supported service families list");
                    var supportedFamilies = ParseSupportedFamilies(flap.Data);
                    await SendServiceVersionsRequestAsync(supportedFamilies);
                }

                Debug.WriteLine($"[BOS] Unexpected SNAC 0x{family:X4}/0x{subtype:X4}, ignoring...");
            }
        }



        // ══════════════════════════════════════════════════════════════════
        // "Сырой" (raw) движок чтения из сокета — обязателен по документации
        // Microsoft при использовании StreamSocket вместе с ControlChannelTrigger:
        // "your app must use a raw async pattern for handling reads instead
        // of the await model... An outstanding socket receive must be kept
        // posted at all times... the app has to post another read before it
        // returns control from the completion callback."
        //
        // await _reader.LoadAsync(...) НАПРЯМУЮ на сокете, привязанном к CCT,
        // ломает всё — от нативных крашей процесса до тихих зависаний ровно
        // там, где вы это наблюдаете (после настройки сервисов). Здесь
        // низкоуровневое чтение идёт через IAsyncOperation.Completed (без
        // await), а весь остальной код (ReceiveFlapAsync и всё, что на нём
        // построено — ReceiveSnacWithTimeout, InitServicesAsync и т.д.)
        // продолжает работать через await на TaskCompletionSource, который
        // наполняется этим движком — поэтому остальной код не менялся.
        private readonly object _flapQueueLock = new object();
        private readonly Queue<FlapFrame> _flapQueue = new Queue<FlapFrame>();
        private TaskCompletionSource<bool> _flapArrivedTcs;
        private Exception _readerFatalError;

        // Вызывается один раз сразу после создания нового _reader
        // (ConnectAsync / ConnectToBosSocketAsync) — обнуляет состояние
        // предыдущего соединения и запускает первое "висящее" чтение.
        private void StartRawReceiveLoop()
        {
            lock (_flapQueueLock)
            {
                _flapQueue.Clear();
                _readerFatalError = null;
                _flapArrivedTcs = null;
            }
            PostNextHeaderRead();
        }

        private void PostNextHeaderRead()
        {
            var reader = _reader;
            if (reader == null) return;

            try
            {
                IAsyncOperation<uint> op = reader.LoadAsync(6);
                op.Completed = (asyncInfo, status) => OnHeaderReadCompleted(asyncInfo, status, reader);
            }
            catch (Exception ex)
            {
                FailReader(ex);
            }
        }

        private void OnHeaderReadCompleted(IAsyncOperation<uint> asyncInfo, AsyncStatus status, DataReader reader)
        {
            try
            {
                if (status != AsyncStatus.Completed)
                {
                    FailReader(asyncInfo.ErrorCode ?? new Exception("Header read failed, status=" + status));
                    return;
                }

                uint headerRead = asyncInfo.GetResults();
                if (headerRead < 6)
                {
                    FailReader(new Exception("Connection closed by remote host"));
                    return;
                }

                byte[] header = new byte[6];
                reader.ReadBytes(header);

                var flap = FlapFrame.Parse(header);
                if (flap == null || flap.StartMarker != 0x2A)
                {
                    FailReader(new Exception("Invalid FLAP header"));
                    return;
                }

                if (flap.DataLength == 0)
                {
                    flap.Data = new byte[0];
                    EnqueueFlap(flap);
                    PostNextHeaderRead(); // репостим ДО возврата из callback'а — требование документации
                    return;
                }

                IAsyncOperation<uint> dataOp = reader.LoadAsync(flap.DataLength);
                dataOp.Completed = (op2, st2) => OnDataReadCompleted(op2, st2, flap, reader);
            }
            catch (Exception ex)
            {
                FailReader(ex);
            }
        }

        private void OnDataReadCompleted(IAsyncOperation<uint> asyncInfo, AsyncStatus status, FlapFrame flap, DataReader reader)
        {
            try
            {
                if (status != AsyncStatus.Completed)
                {
                    FailReader(asyncInfo.ErrorCode ?? new Exception("Data read failed, status=" + status));
                    return;
                }

                uint dataRead = asyncInfo.GetResults();
                if (dataRead < flap.DataLength)
                {
                    FailReader(new Exception("Connection closed during data read"));
                    return;
                }

                flap.Data = new byte[flap.DataLength];
                reader.ReadBytes(flap.Data);

                EnqueueFlap(flap);
            }
            catch (Exception ex)
            {
                FailReader(ex);
                return;
            }

            // ВАЖНО: следующее чтение постим ДО выхода из callback'а —
            // именно это и требует ControlChannelTrigger для корректной
            // синхронизации с IBackgroundTask.Run.
            PostNextHeaderRead();
        }

        private void EnqueueFlap(FlapFrame flap)
        {
            TaskCompletionSource<bool> toSignal = null;
            lock (_flapQueueLock)
            {
                _flapQueue.Enqueue(flap);
                if (_flapArrivedTcs != null)
                {
                    toSignal = _flapArrivedTcs;
                    _flapArrivedTcs = null;
                }
            }
            toSignal?.TrySetResult(true);

            try { ControlChannelService.Instance.NotifyDataReceived(); } catch { }
        }

        private void FailReader(Exception ex)
        {
            TaskCompletionSource<bool> toSignal = null;
            lock (_flapQueueLock)
            {
                _readerFatalError = ex;
                if (_flapArrivedTcs != null)
                {
                    toSignal = _flapArrivedTcs;
                    _flapArrivedTcs = null;
                }
            }
            toSignal?.TrySetException(ex);
            Debug.WriteLine("[RawReceive] Fatal: " + ex.Message);

            // Уведомляем о потере соединения
            if (ConnectionLost != null) ConnectionLost();
            try { _receiveCts?.Cancel(); } catch { }
        }

        // Публичный (для остального кода файла) метод чтения — просто
        // читает из очереди, наполняемой сырым движком выше. Сигнатура и
        // поведение снаружи не изменились, поэтому ReceiveFlapWithTimeout,
        // ReceiveSnacWithTimeout, InitServicesAsync и т.д. не меняются.
        private async Task<FlapFrame> ReceiveFlapAsync(CancellationToken cancellationToken = default(CancellationToken))
        {
            while (true)
            {
                TaskCompletionSource<bool> waitTcs;
                lock (_flapQueueLock)
                {
                    if (_flapQueue.Count > 0)
                        return _flapQueue.Dequeue();

                    if (_readerFatalError != null)
                        throw _readerFatalError;

                    waitTcs = new TaskCompletionSource<bool>();
                    _flapArrivedTcs = waitTcs;
                }

                using (cancellationToken.Register(() => waitTcs.TrySetCanceled()))
                {
                    await waitTcs.Task;
                }
            }
        }

        public System.Collections.ObjectModel.ObservableCollection<Contact> GetCachedContacts()
        {
            return contacts;
        }


        private async Task<FlapFrame> ReceiveFlapWithTimeout(TimeSpan timeout)
        {
            using (var cts = new CancellationTokenSource(timeout))
            {
                try
                {
                    return await ReceiveFlapAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    Debug.WriteLine("[Timeout] No response from server");
                    return null;
                }

            }
        }

        private async Task WaitForServiceVersionsAsync()
        {
            Debug.WriteLine("[Init] Waiting for SNAC 0x01/0x18 (Service Versions Response)");
            StatusUpdater?.Invoke("Ждем версии сервисов...");
            for (int i = 0; i < 10; i++)
            {
                var flap = await ReceiveFlapWithTimeout(TimeSpan.FromSeconds(5));
                if (flap == null || flap.Channel != 0x02 || flap.Data.Length < 10)
                    continue;

                ushort family = (ushort)((flap.Data[0] << 8) | flap.Data[1]);
                ushort subtype = (ushort)((flap.Data[2] << 8) | flap.Data[3]);

                if (family == 0x0001 && subtype == 0x0018)
                {
                    Debug.WriteLine("[Init] Received SNAC 0x01/0x18 — Service Versions Confirmed");
                    return;
                }
                else
                {
                    Debug.WriteLine($"[Init] Ignoring SNAC 0x{family:X4}/0x{subtype:X4}");
                }
            }

            Debug.WriteLine("[Init] Did not receive SNAC 0x01/0x18");
        }


        private Dictionary<ushort, TLV> ParseTlvs(byte[] data)
        {
            var dict = new Dictionary<ushort, TLV>();
            using (var ms = new MemoryStream(data))
            {
                while (ms.Position + 4 <= ms.Length)
                {
                    // Read type (big-endian)
                    byte[] typeBytes = new byte[2];
                    ms.Read(typeBytes, 0, 2);
                    ushort type = (ushort)((typeBytes[0] << 8) | typeBytes[1]);  // Fixed: added closing parenthesis

                    // Read length (big-endian)
                    byte[] lengthBytes = new byte[2];
                    ms.Read(lengthBytes, 0, 2);
                    ushort length = (ushort)((lengthBytes[0] << 8) | lengthBytes[1]);  // Also fixed same issue here

                    // Verify we have enough data
                    if (ms.Position + length > ms.Length)
                    {
                        Debug.WriteLine($"[ParseTLV ERROR] TLV 0x{type:X4} length {length} exceeds remaining data");
                        break;
                    }

                    // Read value (EXACT bytes, no modification)
                    byte[] value = new byte[length];
                    int bytesRead = ms.Read(value, 0, length);

                    if (bytesRead != length)
                    {
                        Debug.WriteLine($"[ParseTLV ERROR] For TLV 0x{type:X4}, expected {length} bytes, got {bytesRead}");
                        continue;
                    }

                    dict[type] = new TLV(type, value);
                }
            }
            return dict;
        }
        public async Task InitializeOscarSessionAsync(uint statusCode)
        {
            Debug.WriteLine("[Init] Starting OSCAR session initialization...");
            try
            {
                var response = await ReceiveSnacWithTimeout(0x0001, 0x0018, TimeSpan.FromSeconds(5));
                if (response == null)
                {
                    Debug.WriteLine("[Init ERROR] Timeout waiting for SNAC 0x01/0x18");
                    return;
                }
                Debug.WriteLine("[Init] Received SNAC 0x01/0x18");

                // Login Stage II (protocol negotiation), финальная часть по спецификации:
                // клиент обязан запросить рейт-лимиты SNAC(01,06), получить SNAC(01,07)
                // и подтвердить их через SNAC(01,08) — только после этого соединение
                // считается "ready". Раньше этот шаг пропускался и сервер это прощал;
                // судя по всему, обновлённый iserverd теперь строго этого требует и
                // рвёт соединение, если ack не пришёл.
                await SendSnacAsync(0x01, 0x06, 0x0000, GetNextRequestID(), null);
                var rateLimitsSnac = await ReceiveSnacWithTimeout(0x0001, 0x0007, TimeSpan.FromSeconds(15));
                if (rateLimitsSnac != null)
                {
                    await SendRateLimitsAckAsync(rateLimitsSnac.Data);
                    Debug.WriteLine("[Init] Rate limits handshake завершён (01,06 -> 01,07 -> 01,08)");
                }
                else
                {
                    Debug.WriteLine("[Init WARNING] Не получили SNAC(01,07) — сервер может позже разорвать соединение");
                }

                // Отправляем все запросы и получаем контакты
                await InitServicesAsync();
                await Task.Delay(200);

                // SNAC(02,04) — capabilities
                await SendClientCapabilitiesAsync();
                await Task.Delay(200);

                // SNAC(01,1E) — статус
                await SendSetStatusAsync(statusCode);
                await Task.Delay(200);

                // активация КЛ
                await SendSnacAsync(0x13, 0x07, 0x0000, GetNextRequestID(), null);
                await Task.Delay(200);

                // SNAC(01,02) — ClientReady
                await SendClientReadyAsync();
                await Task.Delay(200);

                // Jasmine: дополнительные шаги после roster ack
                // SNAC(15,02) — запрос собственной контактной инфы
                await SendOwnInfoRequest();
                await Task.Delay(100);
                // SSI Edit — установка visibility
                await SetVisibilityS();
                await Task.Delay(100);
                // SNAC(15,02) — запрос офлайн-сообщений
                await SendOfflineMsgsRequest();
                await Task.Delay(100);

                await _dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                {
                    ((App)Windows.UI.Xaml.Application.Current).NotifyConnected();
                });


                // SNAC(13,07) — активация SSI (после ClientReady как в QIP)
                

                Debug.WriteLine("[Init] Инициализация завершена");

                // Receive loop НЕ запускаем здесь — его запускает и им владеет
                // вызывающая сторона (ReconnectService.MonitorLoopAsync), чтобы
                // не было двух параллельных читателей одного сокета, что само
                // по себе тоже рвёт соединение с той же ошибкой.
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Init ERROR] {ex}");
                throw;
            }
        }

        private async Task InitServicesAsync()
        {
            Debug.WriteLine("[InitServices] Начало...");
            StatusUpdater?.Invoke("Настраиваем сервисы...");

            // Шлём ВСЕ запросы подряд с микропаузами (rate-limit защита как в Jasmine)
            await SendSnacAsync(0x01, 0x0E, 0x00, GetNextRequestID(), null);
            await Task.Delay(30);

            byte[] ssiParamBody = new byte[] { 0x00, 0x0b, 0x00, 0x02, 0x00, 0x0f };
            await SendSnacAsync(0x13, 0x02, 0x00, GetNextRequestID(), ssiParamBody);
            await Task.Delay(30);

            await SendSnacAsync(0x13, 0x04, 0x00, GetNextRequestID(), null);
            await Task.Delay(30);
            await SendSnacAsync(0x02, 0x02, 0x00, GetNextRequestID(), null);
            await Task.Delay(30);

            byte[] blmParamBody = new byte[] { 0x00, 0x05, 0x00, 0x02, 0x00, 0x03 };
            await SendSnacAsync(0x03, 0x02, 0x00, GetNextRequestID(), blmParamBody);
            await Task.Delay(30);

            await SendSnacAsync(0x04, 0x04, 0x00, GetNextRequestID(), null);
            await Task.Delay(30);
            await SendSnacAsync(0x09, 0x02, 0x00, GetNextRequestID(), null);

            Debug.WriteLine("[InitServices] Все запросы отправлены, ждём ответы...");

            // Один общий цикл — собираем все ответы
            bool gotContacts = false;
            bool gotIcbmParams = false;
            var parsedContacts = new ObservableCollection<Contact>();
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);

            while (DateTime.UtcNow < deadline)
            {
                var flap = await ReceiveFlapWithTimeout(TimeSpan.FromSeconds(5));
                if (flap == null || flap.Channel != 0x02 || flap.Data.Length < 10)
                {
                    if (gotContacts) break; // если контакты уже есть — выходим при таймауте
                    continue;
                }

                var snac = SnacPacket.Parse(flap.Data);
                if (snac == null) continue;

                Debug.WriteLine("[InitServices] SNAC(" + snac.Family.ToString("X2") +
                                "," + snac.Subtype.ToString("X2") + ")");

                if (snac.Family == 0x13 && snac.Subtype == 0x03)
                {
                    Debug.WriteLine("[Init] Got SSI params");
                }
                else if (snac.Family == 0x04 && snac.Subtype == 0x05)
                {
                    ParseIcbmParams(snac.Data);
                    gotIcbmParams = true;
                    Debug.WriteLine("[Init] Got ICBM params, sending SNAC(04,02)...");
                    // ТОЛЬКО ТЕПЕРЬ шлём SetIcbmParameters — после получения 04,05
                    await SendIcbmParametersAsync();
                }
                else if (snac.Family == 0x02 && snac.Subtype == 0x03)
                {
                    Debug.WriteLine("[Init] Got location params");
                }
                else if (snac.Family == 0x03 && snac.Subtype == 0x03)
                {
                    Debug.WriteLine("[Init] Got BLM params");
                }
                else if (snac.Family == 0x09 && snac.Subtype == 0x03)
                {
                    Debug.WriteLine("[Init] Got privacy params");
                }
                else if (snac.Family == 0x01 && snac.Subtype == 0x0F)
                {
                    Debug.WriteLine("[Init] Got own info");
                }
                else if (snac.Family == 0x13 && snac.Subtype == 0x06)
                {
                    ParseContactListPacket(snac.Data, parsedContacts);
                    Debug.WriteLine("[Init] Got contacts: " + parsedContacts.Count);
                    if (!SnacFlags.HasMoreData(snac.Flags))
                    {
                        gotContacts = true;
                        // Не выходим сразу — ждём ещё ICBM params если не получили
                        if (gotIcbmParams) break;
                    }
                }
            }

            if (!gotIcbmParams)
            {
                Debug.WriteLine("[Init] ICBM params not received, sending defaults");
                await SendIcbmParametersAsync();
            }

            // Обновляем коллекцию контактов
            if (this.contacts == null)
            {
                this.contacts = parsedContacts;
            }
            else
            {
                await _dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                {
                    this.contacts.Clear();
                    foreach (var c in parsedContacts)
                        this.contacts.Add(c);
                });
            }

            Debug.WriteLine("[InitServices] Готово. Контактов: " + parsedContacts.Count);
        }


        private async Task SendRateLimitsAckAsync(byte[] data)
        {
            // SNAC(01,07) содержит: ushort classCount, затем для каждого класса ushort classId + много данных
            // Нам нужно извлечь classId каждого класса и подтвердить их через SNAC(01,08)
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                try
                {
                    int offset = 0;
                    if (offset + 2 > data.Length) return;
                    ushort classCount = ReadU16(data, ref offset);
                    Debug.WriteLine($"[RateLimitsAck] classCount={classCount}");

                    for (int i = 0; i < classCount; i++)
                    {
                        if (offset + 2 > data.Length) break;
                        ushort classId = ReadU16(data, ref offset);
                        writer.Write(SwapUInt16(classId));

                        // Каждый класс содержит ещё 33 байта данных (window size, clear/alert/limit/disconnect/current level + flags)
                        offset += 33;
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[RateLimitsAck ERROR] {ex.Message}");
                    return;
                }

                byte[] payload = ms.ToArray();
                if (payload.Length > 0)
                {
                    await SendSnacAsync(0x01, 0x08, 0x00, GetNextRequestID(), payload);
                    Debug.WriteLine($"[RateLimitsAck] Sent SNAC(01,08) with {payload.Length / 2} class IDs");
                }
            }
        }

        // Jasmine createSetICBM: один вызов channel=0, flags=0x070B
        private const ushort ICBM_CHANNEL = 0;
        private const uint ICBM_FLAGS = 0x0000070B;

        private async Task SendIcbmParametersAsync()
        {
            using (var ms = new MemoryStream())
            {
                WriteU16BE(ms, ICBM_CHANNEL);       // channel = 0
                WriteU32BE(ms, ICBM_FLAGS);          // flags = 0x070B (1803)
                WriteU16BE(ms, 8000);                // maxSize = 8000
                WriteU16BE(ms, 999);                 // max sender warn
                WriteU16BE(ms, 999);                 // max receiver warn
                WriteU16BE(ms, 0);                   // min interval
                WriteU16BE(ms, 0);                   // unknown
                await SendSnacAsync(0x04, 0x02, 0x0000, GetNextRequestID(), ms.ToArray());
                Debug.WriteLine("[ICBM] SNAC(04,02) Jasmine format (channel=0)");
            }
        }



        // Jasmine createContactInfoRequest — запрос собственной контактной инфы (15,02)
        private async Task SendOwnInfoRequest()
        {
            uint myUin;
            if (!uint.TryParse(_uin, out myUin)) return;
            int rid = (int)((DateTime.UtcNow.Ticks >> 32) & 0x00FFFFFF);
            using (var data = new MemoryStream())
            using (var body = new MemoryStream())
            {
                WriteU16LE(body, 0x0010);
                WriteU16LE(body, 0x000E);
                WriteU32LE(body, myUin);
                WriteU16LE(body, 0xD001);
                WriteU16LE(body, (ushort)(_flapSequenceNumber + 1));
                WriteU16LE(body, 0xB204);
                WriteU32LE(body, myUin);
                byte[] bodyBytes = body.ToArray();
                WriteU16BE(data, 0x0001); WriteU16BE(data, (ushort)bodyBytes.Length);
                data.Write(bodyBytes, 0, bodyBytes.Length);
                await SendSnacAsync(0x15, 0x02, 0x0000, (uint)rid, data.ToArray());
                Debug.WriteLine("[OwnInfo] SNAC(15,02) own contact info request");
            }
        }

        // Jasmine createOfflineMsgsRequest — запрос офлайн-сообщений (15,02)
        private async Task SendOfflineMsgsRequest()
        {
            uint myUin;
            if (!uint.TryParse(_uin, out myUin)) return;
            using (var data = new MemoryStream())
            using (var body = new MemoryStream())
            {
                WriteU16BE(body, 0x0800);
                WriteU32LE(body, myUin);
                WriteU16BE(body, 0x3C00);
                WriteU16BE(body, (ushort)(_flapSequenceNumber + 1));
                byte[] bodyBytes = body.ToArray();
                WriteU16BE(data, 0x0001); WriteU16BE(data, (ushort)bodyBytes.Length);
                data.Write(bodyBytes, 0, bodyBytes.Length);
                await SendSnacAsync(0x15, 0x02, 0x0000, 64017, data.ToArray());
                Debug.WriteLine("[OfflineMsgs] SNAC(15,02) offline msgs request");
            }
        }

        // Jasmine setVisibilityS — SSI Edit (begin → update → end)
        private async Task SetVisibilityS()
        {
            await SendSnacAsync(0x13, 0x11, 0x0000, GetNextRequestID(), null);
            using (var ms = new MemoryStream())
            {
                WriteU32BE(ms, 0x00000000);
                WriteU16BE(ms, 0x0000); WriteU16BE(ms, 0x0004);
                WriteU16BE(ms, 0x0005);
                WriteU16BE(ms, 0x00CA); WriteU16BE(ms, 0x0001);
                ms.WriteByte(0x01);
                await SendSnacAsync(0x13, 0x09, 0x0000, 135185, ms.ToArray());
            }
            await SendSnacAsync(0x13, 0x12, 0x0000, GetNextRequestID(), null);
        }

        private async Task ClientIdentAsync()
        {
            // здесь сделать SNAC(02,04)
        }

        private byte[] GetMyCapabilities()
        {
            // ICQ capabilities: например, поддержка UTF-8, file transfers и т.д.
            return new byte[]
            {
        0x09, 0x46, 0x13, 0x4C, 0x4C, 0x7F, 0x11, 0xD1,
        0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00  // пример capabilities (UTF-8)
            };
        }




        private ushort ReadUInt16(byte[] buffer, ref int offset)
        {
            ushort val = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            offset += 2;
            return val;
        }


        /*     private async Task HandleIncomingBuddySnacsAsync()
             {
                 while (true)
                 {
                     var snac = await ReceiveSnacAsync();

                     if (snac.Family == 0x03 && snac.Subtype == 0x0B)
                     {
                         HandleUserOnline(snac.Data);
                     }
                     else if (snac.Family == 0x03 && snac.Subtype == 0x0C)
                     {
                         HandleUserOffline(snac.Data);
                     }
                     else if (snac.Family == 0x03 && snac.Subtype == 0x0F)
                     {
                         HandleXStatusChanged(snac.Data);
                     }
                 }
             }

             private void HandleUserOnline(byte[] data)
             {
                 int offset = 0;
                 string uin = ReadString(data, ref offset);
                 uint status = BitConverter.ToUInt32(data, offset); offset += 4;
                 uint xstatus = ExtractXStatus(data, offset); // реализуй, если нужно

                 AddOrUpdateContact(uin, status, xstatus, isOnline: true);
             }
             */

        private byte[] BuildCapabilitiesPayload()
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                // TLV 0x01 - MIME type
                writer.Write(SwapUInt16(0x01)); // Type
                writer.Write(SwapUInt16(0x10)); // Length
                writer.Write(Encoding.UTF8.GetBytes("text/x-aolrtf"));
                writer.Write(new byte[16 - "text/x-aolrtf".Length]); // Padding if needed

                // TLV 0x05 - Capabilities (можно задать 1–2 GUID'а)
                writer.Write(SwapUInt16(0x05));
                writer.Write(SwapUInt16(16));
                writer.Write(new byte[16]); // Заглушка (можно заменить на реальные CLSID)

                return ms.ToArray();
            }
        }

        private async Task<FlapFrame> ReceiveSnacAsync(ushort expectedFamily, ushort expectedSubtype)
        {
            while (true)
            {
                var flap = await ReceiveFlapAsync();
                if (flap == null || flap.Data.Length < 10)
                    continue;

                ushort family = (ushort)((flap.Data[0] << 8) | flap.Data[1]);
                ushort subtype = (ushort)((flap.Data[2] << 8) | flap.Data[3]);

                if (family == expectedFamily && subtype == expectedSubtype)
                    return flap;
            }
        }


        private byte[] BuildSsiCheckPayload()
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write(SwapUInt16(0x0000)); // Last modification time
                writer.Write(SwapUInt16(0x0000)); // Items count
                return ms.ToArray();
            }
        }


        public async Task<SnacPacket> ReceiveSnacWithTimeout(ushort expectedFamily, ushort expectedSubtype, TimeSpan timeout)
        {
            var deadline = DateTime.UtcNow + timeout;

            while (DateTime.UtcNow < deadline)
            {
                try
                {
                    var flap = await ReceiveFlapWithTimeout(deadline - DateTime.UtcNow);

                    if (flap == null || flap.Channel != 0x02 || flap.Data.Length < 10)
                    {
                        Debug.WriteLine("[ReceiveSnac] Пропущен некорректный или пустой FLAP");
                        continue;
                    }

                    var snac = SnacPacket.Parse(flap.Data);
                    if (snac == null)
                        continue;

                    Debug.WriteLine($"[ReceiveSnac] Получен SNAC 0x{snac.Family:X4}/0x{snac.Subtype:X4}");

                    if (snac.Family == expectedFamily && snac.Subtype == expectedSubtype)
                    {
                        Debug.WriteLine($"[ReceiveSnac] Совпадение SNAC 0x{snac.Family:X4}/0x{snac.Subtype:X4}, длина={snac.Data.Length}");
                        return snac;
                    }
                    else
                    {
                        Debug.WriteLine($"[ReceiveSnac] Ожидался SNAC 0x{expectedFamily:X4}/0x{expectedSubtype:X4}, но пришёл 0x{snac.Family:X4}/0x{snac.Subtype:X4}");
                    }
                }
                catch (TimeoutException)
                {
                    Debug.WriteLine("[ReceiveSnac] Таймаут при ожидании SNAC");
                    break;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[ReceiveSnac] Ошибка: {ex.Message}");
                    break;
                }
            }

            return null;
        }





        public async Task<ObservableCollection<Contact>> GetContactsAsync(uint statusCode)
        {
            // contacts уже заполнен в InitServicesAsync
            if (this.contacts != null && this.contacts.Count > 0)
            {
                Debug.WriteLine($"[GetContacts] Returning cached contacts: {this.contacts.Count}");
                return this.contacts;
            }

            // Если по какой-то причине пусто — возвращаем пустой список
            Debug.WriteLine("[GetContacts] contacts is empty");
            return new ObservableCollection<Contact>();
        }

        // Jasmine createSetUserInfo: 8 GUID-ов (OSCAR ×2, UTF-8, Unicode, File, Typing, Xtraz, RTF)
        private static readonly byte[][] MY_CAPABILITIES = {
            HexToBytes("094600004C7F11D18222444553540000"), // OSCAR standard
            HexToBytes("094613494C7F11D18222444553540000"), // ICQ UTF-8
            HexToBytes("0946134E4C7F11D18222444553540000"), // Unicode
            HexToBytes("094613434C7F11D18222444553540000"), // File transfer
            HexToBytes("563FC8090B6F41BD9F79422609DFA2F3"), // Typing notify
            HexToBytes("1A093C6CD7FD4EC59D51A6474E34F5A0"), // Xtraz
            HexToBytes("094600004C7F11D18222444553540000"), // OSCAR standard (repeat)
            HexToBytes("0946134D4C7F11D18222444553540000"), // RTF messages
        };

        private async Task SendClientCapabilitiesAsync()
        {
            using (var ms = new MemoryStream())
            using (var caps = new MemoryStream())
            {
                foreach (var g in MY_CAPABILITIES) caps.Write(g, 0, 16);
                byte[] capsData = caps.ToArray();
                WriteU16BE(ms, 0x0005);
                WriteU16BE(ms, (ushort)capsData.Length);
                ms.Write(capsData, 0, capsData.Length);
                await SendSnacAsync(0x02, 0x04, 0x0000, GetNextRequestID(), ms.ToArray());
                Debug.WriteLine("[Caps] SNAC(02,04) Jasmine 8 GUIDs");
            }
        }




        private static byte[] HexToBytes(string hex)
        {
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }


        public void ParseContactListPacket(byte[] data, ObservableCollection<Contact> contacts)
        {
            if (data == null || data.Length < 5) return;

            try
            {
                int offset = 0;
                byte version = data[offset++];
                ushort itemCount = ReadU16(data, ref offset);
                Debug.WriteLine("[ParseContactListPacket] Item count: " + itemCount);

                // Временные списки для двухпроходного парсинга
                var tempContacts = new System.Collections.Generic.List<Contact>();
                var tempGroups = new System.Collections.Generic.Dictionary<ushort, SsiGroup>();

                for (int i = 0; i < itemCount; i++)
                {
                    if (offset + 2 > data.Length) break;
                    ushort nameLen = ReadU16(data, ref offset);
                    if (offset + nameLen > data.Length) break;
                    string name = Encoding.UTF8.GetString(data, offset, nameLen);
                    offset += nameLen;

                    if (offset + 8 > data.Length) break;
                    ushort groupId = ReadU16(data, ref offset);
                    ushort itemId = ReadU16(data, ref offset);
                    ushort itemType = ReadU16(data, ref offset);
                    ushort tlvBlockLen = ReadU16(data, ref offset);

                    int tlvEnd = offset + tlvBlockLen;
                    if (tlvEnd > data.Length) break;

                    string displayName = null;
                    var memberIds = new System.Collections.Generic.List<ushort>();

                    int tlvOffset = offset;
                    while (tlvOffset + 4 <= tlvEnd)
                    {
                        ushort tlvType = ReadU16(data, ref tlvOffset);
                        ushort tlvValueLen = ReadU16(data, ref tlvOffset);
                        if (tlvOffset + tlvValueLen > tlvEnd) break;

                        switch (tlvType)
                        {
                            case 0x0131:
                                if (tlvValueLen > 0)
                                    displayName = Encoding.UTF8.GetString(
                                        data, tlvOffset, tlvValueLen);
                                break;
                            case 0x00C8: // member list для групп
                                for (int m = 0; m + 2 <= tlvValueLen; m += 2)
                                {
                                    int moff = tlvOffset + m;
                                    memberIds.Add((ushort)((data[moff] << 8) | data[moff + 1]));
                                }
                                break;
                        }
                        tlvOffset += tlvValueLen;
                    }

                    offset = tlvEnd;

                    switch (itemType)
                    {
                        case 0x0000: // Buddy
                            string finalName = !string.IsNullOrEmpty(displayName)
                                ? displayName : name;
                            tempContacts.Add(new Contact
                            {
                                Uin = name,
                                Name = finalName,
                                GroupId = groupId,
                                ItemId = itemId,
                                StatusIcon = "/Assets/statuses/offline.png",
                                IsNewOnline = false
                            });
                            Debug.WriteLine("[ParseContactListPacket] Buddy: " + finalName +
                                            " uin=" + name + " groupId=" + groupId +
                                            " itemId=" + itemId);
                            break;

                        case 0x0001:
                            {
                                var g = new SsiGroup
                                {
                                    GroupId = groupId,
                                    ItemId = itemId,
                                    Name = name, // "Контакты" придёт как name для groupId=0
                                    MemberIds = memberIds
                                };
                                tempGroups[groupId] = g;
                                _ssiGroups[groupId] = g;
                                Debug.WriteLine("[ParseContactListPacket] Group: " + name +
                                                " groupId=" + groupId + " members=" + memberIds.Count);
                                break;
                            }

                        case 0x0002: Debug.WriteLine("[ParseContactListPacket] Permit: " + name); break;
                        case 0x0003: Debug.WriteLine("[ParseContactListPacket] Deny: " + name); break;
                        case 0x0004: Debug.WriteLine("[ParseContactListPacket] Visibility settings"); break;
                        case 0x000E: Debug.WriteLine("[ParseContactListPacket] Ignore: " + name); break;
                        case 0x000F: Debug.WriteLine("[ParseContactListPacket] Last update date"); break;
                        default:
                            Debug.WriteLine("[ParseContactListPacket] Unknown type 0x" +
                                            itemType.ToString("X4") + " name=" + name);
                            break;
                    }
                }

                // Второй проход — заполняем Group у контактов по groupId
                foreach (var contact in tempContacts)
                {
                    if (tempGroups.ContainsKey(contact.GroupId))
                        contact.Group = tempGroups[contact.GroupId].Name;
                    else
                        contact.Group = ""; // groupId=0 или неизвестная группа

                    contacts.Add(contact);
                }

                // Время последнего изменения
                if (offset + 4 <= data.Length)
                {
                    uint lastChange = ReadU32(data, ref offset);
                    Debug.WriteLine("[ParseContactListPacket] Last change time: " + lastChange);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[ParseContactListPacket ERROR] " + ex);
            }
        }

        // Вспомогательный: строим SSI item для отправки
        private byte[] BuildSsiItem(string name, ushort groupId, ushort itemId,
                                      ushort itemType, byte[] tlvData)
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                byte[] nameBytes = Encoding.UTF8.GetBytes(name ?? "");
                writer.Write(SwapUInt16((ushort)nameBytes.Length));
                writer.Write(nameBytes);
                writer.Write(SwapUInt16(groupId));
                writer.Write(SwapUInt16(itemId));
                writer.Write(SwapUInt16(itemType));

                if (tlvData != null && tlvData.Length > 0)
                {
                    writer.Write(SwapUInt16((ushort)tlvData.Length));
                    writer.Write(tlvData);
                }
                else
                {
                    writer.Write(SwapUInt16(0x0000)); // нет TLV
                }

                return ms.ToArray();
            }
        }

        // Удалить контакт
        public async Task RemoveContactAsync(Contact contact)
        {
            Debug.WriteLine("[SSI] Removing " + contact.Uin);

            await SendSnacAsync(0x13, 0x0A, 0x00, GetNextRequestID(),
                BuildSsiItem(contact.Uin, contact.GroupId, contact.ItemId,
                             0x0000, null));

            ushort r1 = await WaitForSsiAck();
            Debug.WriteLine("[SSI] Remove buddy result: " + GetSsiResultText(r1));
            if (r1 != 0x0000)
                throw new Exception("SSI ошибка удаления: " + GetSsiResultText(r1));

            await Task.Delay(150);

            if (_ssiGroups.ContainsKey(contact.GroupId))
            {
                var group = _ssiGroups[contact.GroupId];
                group.MemberIds.Remove(contact.ItemId);

                byte[] c8Data = new byte[group.MemberIds.Count * 2];
                for (int i = 0; i < group.MemberIds.Count; i++)
                {
                    c8Data[i * 2] = (byte)(group.MemberIds[i] >> 8);
                    c8Data[i * 2 + 1] = (byte)(group.MemberIds[i] & 0xFF);
                }

                await SendSnacAsync(0x13, 0x11, 0x00, GetNextRequestID(), null);
                await Task.Delay(100);

                await SendSnacAsync(0x13, 0x09, 0x00, GetNextRequestID(),
                    BuildSsiItem(group.Name, group.GroupId, 0x0000,
                                 0x0001, BuildTlv(0x00C8, c8Data)));

                await SendSnacAsync(0x13, 0x12, 0x00, GetNextRequestID(), null);

                ushort r2 = await WaitForSsiAck();
                Debug.WriteLine("[SSI] Update group result: " + GetSsiResultText(r2));
            }

            if (contacts != null)
            {
                var c = contacts.FirstOrDefault(x => x.Uin == contact.Uin);
                if (c != null)
                    await _dispatcher.RunAsync(CoreDispatcherPriority.Normal,
                        () => contacts.Remove(c));
            }

            if (ContactRemoved != null) ContactRemoved(contact.Uin);
            Debug.WriteLine("[SSI] Removed: " + contact.Uin);
        }

        // Переименовать контакт
        public async Task RenameContactAsync(Contact contact, string newName)
        {
            Debug.WriteLine("[SSI] Renaming " + contact.Uin + " -> " + newName);

            byte[] nameTlv = BuildTlv(0x0131, Encoding.UTF8.GetBytes(newName));

            await SendSnacAsync(0x13, 0x11, 0x00, GetNextRequestID(), null);
            await Task.Delay(100);

            await SendSnacAsync(0x13, 0x09, 0x00, GetNextRequestID(),
                BuildSsiItem(contact.Uin, contact.GroupId, contact.ItemId,
                             0x0000, nameTlv));

            await SendSnacAsync(0x13, 0x12, 0x00, GetNextRequestID(), null);

            // Ждём через событие — не блокируем receive loop
            ushort result = await WaitForSsiAck();
            Debug.WriteLine("[SSI] Rename result: " + GetSsiResultText(result));

            if (result == 0x0000)
            {
                contact.Name = newName;
                if (contacts != null)
                {
                    var c = contacts.FirstOrDefault(x => x.Uin == contact.Uin);
                    if (c != null)
                        await _dispatcher.RunAsync(CoreDispatcherPriority.Normal,
                            () => c.Name = newName);
                }
                if (ContactRenamed != null) ContactRenamed(contact.Uin, newName);
            }
            else
                throw new Exception("SSI ошибка: " + GetSsiResultText(result));
        }

        // Перенести контакт в другую группу
        public async Task MoveContactAsync(Contact contact, ushort newGroupId)
        {
            if (!_ssiGroups.ContainsKey(newGroupId))
            {
                Debug.WriteLine("[SSI] Target group not found: " + newGroupId);
                return;
            }

            var oldGroup = _ssiGroups.ContainsKey(contact.GroupId)
                ? _ssiGroups[contact.GroupId] : null;
            var newGroup = _ssiGroups[newGroupId];

            await SendSnacAsync(0x13, 0x11, 0x00, GetNextRequestID(), null); // begin edit

            // Удаляем из старой группы
            if (oldGroup != null)
            {
                oldGroup.MemberIds.Remove(contact.ItemId);
                byte[] oldC9 = new byte[oldGroup.MemberIds.Count * 2];
                for (int i = 0; i < oldGroup.MemberIds.Count; i++)
                {
                    oldC9[i * 2] = (byte)(oldGroup.MemberIds[i] >> 8);
                    oldC9[i * 2 + 1] = (byte)(oldGroup.MemberIds[i] & 0xFF);
                }
                await SendSnacAsync(0x13, 0x09, 0x00, GetNextRequestID(),
                    BuildSsiItem(oldGroup.Name, oldGroup.GroupId, oldGroup.ItemId,
                                 0x0001, BuildTlv(0x00C9, oldC9)));
            }

            // Обновляем запись контакта с новым groupId
            await SendSnacAsync(0x13, 0x09, 0x00, GetNextRequestID(),
                BuildSsiItem(contact.Uin, newGroupId, contact.ItemId, 0x0000, null));

            // Добавляем в новую группу
            newGroup.MemberIds.Add(contact.ItemId);
            byte[] newC9 = new byte[newGroup.MemberIds.Count * 2];
            for (int i = 0; i < newGroup.MemberIds.Count; i++)
            {
                newC9[i * 2] = (byte)(newGroup.MemberIds[i] >> 8);
                newC9[i * 2 + 1] = (byte)(newGroup.MemberIds[i] & 0xFF);
            }
            await SendSnacAsync(0x13, 0x09, 0x00, GetNextRequestID(),
                BuildSsiItem(newGroup.Name, newGroup.GroupId, newGroup.ItemId,
                             0x0001, BuildTlv(0x00C9, newC9)));

            await SendSnacAsync(0x13, 0x12, 0x00, GetNextRequestID(), null); // end edit

            // Ждём ответы
            await ReceiveSnacWithTimeout(0x13, 0x0E, TimeSpan.FromSeconds(5));
            await ReceiveSnacWithTimeout(0x13, 0x0E, TimeSpan.FromSeconds(5));

            // Обновляем локально
            contact.GroupId = newGroupId;
            contact.Group = newGroup.Name;

            Debug.WriteLine("[SSI] Moved " + contact.Uin + " to group " + newGroup.Name);
        }

        // Получить список групп (для UI)
        public List<SsiGroup> GetGroups()
        {
            return new List<SsiGroup>(_ssiGroups.Values);
        }

        private ushort ReadU16(byte[] data, ref int offset)
        {
            ushort val = (ushort)((data[offset] << 8) | data[offset + 1]);
            offset += 2;
            return val;
        }



        // Jasmine createSetDCInfo: flags WORD + status WORD в TLV 0x0006, protoVer=11
        public async Task SendSetStatusAsync(uint statusCode)
        {
            using (var ms = new MemoryStream())
            {
                // TLV 0x0006: flags WORD + status WORD (как в Jasmine — не DWord!)
                WriteTlvBE(ms, 0x0006, new byte[] { 0x01, 0x00, (byte)(statusCode >> 8), (byte)(statusCode & 0xFF) });
                // TLV 0x0008 — пустой
                WriteTlvBE(ms, 0x0008, new byte[] { 0x00, 0x00 });
                // TLV 0x000C — DC info (protoVer = 11 как в Jasmine)
                using (var dcMs = new MemoryStream())
                {
                    WriteU16BE(dcMs, 0x0000); WriteU16BE(dcMs, 0x0000); // заглушка
                    WriteU32BE(dcMs, 0x00000000);                        // port
                    dcMs.WriteByte(0x04);                                // DC type = 4
                    WriteU16BE(dcMs, 0x000B);                            // protoVersion = 11
                    for (int i = 0; i < 16; i++) dcMs.WriteByte(0x00);
                    WriteU16BE(dcMs, 0x0000);
                    WriteTlvBE(ms, 0x000C, dcMs.ToArray());
                }
                // TLV 0x001F — пустой
                WriteTlvBE(ms, 0x001F, new byte[] { 0x00, 0x00 });

                await SendSnacAsync(0x01, 0x1E, 0x0000, GetNextRequestID(), ms.ToArray());
                Debug.WriteLine($"[SetStatus] SNAC(01,1E) status=0x{(statusCode & 0xFFFF):X4} Jasmine format");
            }
        }



        private async Task<bool> ConnectToBosAsync(string bosHostPort, byte[] cookieBytes, uint statusCode)
        {
            try
            {
                Debug.WriteLine($"[BOS] Connecting to BOS server: {bosHostPort}");
                StatusUpdater?.Invoke("Меняем сервер...");
                // Парсим хост и порт
                string[] parts = bosHostPort.Split(':');
                string host = parts[0];
                string port = parts.Length > 1 ? parts[1] : "5190";

                // Закрываем предыдущее соединение
                _socket?.Dispose();
                _socket = null;

                // [ФИКС]: Обязательно освобождаем аппаратный слот фонового триггера перед созданием нового
                try { ControlChannelService.Instance.Cleanup(); } catch { }

                // Создаем новое соединение
                await ConnectToBosSocketAsync(host, port);

                // 1. Ждем приветствие от сервера (FLAP 0x01)
                Debug.WriteLine("[BOS] Waiting for server hello (FLAP 0x01)...");
                var hello = await ReceiveFlapWithTimeout(TimeSpan.FromSeconds(10));
                if (hello == null || hello.Channel != 0x01)
                {
                    Debug.WriteLine("[BOS] No server hello received.");
                    return false;
                }

                // Проверяем данные приветствия (должны быть 00-00-00-01)
                if (hello.Data.Length != 4 ||
                    hello.Data[0] != 0x00 ||
                    hello.Data[1] != 0x00 ||
                    hello.Data[2] != 0x00 ||
                    hello.Data[3] != 0x01)
                {
                    Debug.WriteLine($"[BOS] Invalid hello data: {BitConverter.ToString(hello.Data)}");
                    return false;
                }

                Debug.WriteLine("[BOS] Received valid server hello. Preparing to send cookie...");

                // 2. Формируем полный пакет для отправки:
                // - 4 байта: 00 00 00 01 (версия протокола)
                // - TLV 0x0006 с cookie (256 байт)
                var payload = new List<byte>();
                payload.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x01 });
                payload.AddRange(BuildTlv(0x0006, cookieBytes));
                StatusUpdater?.Invoke("Отправляем cookie...");
                Debug.WriteLine($"[BOS] Sending cookie packet (length: {payload.Count} bytes)");
                Debug.WriteLine($"[BOS] Cookie data: {BitConverter.ToString(cookieBytes.Take(32).ToArray())}...");

                // 3. Отправляем с рандомным sequence number
                ushort sequence = (ushort)new Random().Next(10000, 60000);
                await SendFlapAsync(0x01, payload.ToArray());

                // 4. Ждем ответа от сервера (SNAC 0x0001/0x0003)
                Debug.WriteLine("[BOS] Waiting for server response (SNAC 0x0001/0x0003)...");
                var response = await ReceiveFlapWithTimeout(TimeSpan.FromSeconds(15));

                if (response == null)
                {
                    Debug.WriteLine("[BOS] No response from server after sending cookie.");
                    return false;
                }

                Debug.WriteLine($"[BOS] Received response: Type=0x{response.Channel:X2}, Length={response.Data.Length}");

                // Проверяем что это SNAC (0x02) с нужными данными
                if (response.Channel == 0x02 && response.Data.Length >= 10)
                {
                    ushort family = (ushort)((response.Data[0] << 8) | response.Data[1]);
                    ushort subtype = (ushort)((response.Data[2] << 8) | response.Data[3]);

                    Debug.WriteLine($"[BOS] Received SNAC: 0x{family:X4}/0x{subtype:X4}");

                    if (family == 0x0001 && subtype == 0x0003)
                    {
                        StatusUpdater?.Invoke("Получили список сервисов...");
                        Debug.WriteLine("[BOS] Successfully connected to BOS server and server sent services list!");
                        var supportedFamilies = ParseSupportedFamilies(response.Data);
                        await SendServiceVersionsRequestAsync(supportedFamilies);
                        return true;
                    }
                }

                Debug.WriteLine("[BOS] Unexpected response from server.");
                Debug.WriteLine($"[BOS] Response data: {BitConverter.ToString(response.Data)}");
                return false;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[BOS ERROR] {ex.Message}");
                return false;
            }
        }

        private async Task ConnectToBosSocketAsync(string host, string port)
        {
            _socket = new StreamSocket();

            // Проверяем включена ли фоновая работа
            object bgMode = Windows.Storage.ApplicationData.Current
                .LocalSettings.Values["BackgroundMode"];
            bool backgroundEnabled = bgMode == null || (bool)bgMode;

            if (backgroundEnabled)
            {
                var trigger = await ControlChannelService.Instance.InitializeAsync();
                if (trigger != null)
                {
                    bool assigned = ControlChannelService.Instance.AssignSocket(_socket);
                    Debug.WriteLine("[ConnectToBos] CCT assigned: " + assigned);
                }
            }
            else
            {
                Debug.WriteLine("[ConnectToBos] Background mode disabled, skipping CCT");
            }

            await _socket.ConnectAsync(new HostName(host), port);

            if (backgroundEnabled)
            {
                try
                {
                    bool pushEnabled = ControlChannelService.Instance.WaitForPushEnabled();
                    Debug.WriteLine("[ConnectToBos] Push enabled: " + pushEnabled);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("[ConnectToBos] WaitForPushEnabled error: " + ex.Message);
                }
            }

            _writer = new DataWriter(_socket.OutputStream);
            _reader = new DataReader(_socket.InputStream)
            {
                InputStreamOptions = InputStreamOptions.Partial,
                ByteOrder = ByteOrder.BigEndian
            };
            StartRawReceiveLoop();
        }

        private async Task<bool> HandleBosRedirectAsync(byte[] data, uint statusCode)
        {
            StatusUpdater?.Invoke("Получили cookie...");
            Debug.WriteLine("[Redirect] Parsing BOS redirect packet...");
            Debug.WriteLine($"[Redirect] Raw TLV data: {BitConverter.ToString(data)}");

            try
            {
                Dictionary<ushort, TLV> tlvs = ParseTlvs(data);
                TLV bosHostTlv;
                TLV cookieTlv;

                // Verify we have required TLVs
                if (!tlvs.TryGetValue(0x0005, out bosHostTlv) ||
                    !tlvs.TryGetValue(0x0006, out cookieTlv))
                {
                    Debug.WriteLine("[Redirect] Missing required TLVs (0x0005 or 0x0006)");
                    return false;
                }

                // Verify cookie length (should be exactly 256 bytes)
                if (cookieTlv.Value.Length != 256)
                {
                    Debug.WriteLine($"[Redirect] Invalid cookie length: {cookieTlv.Value.Length}, expected 256");
                    return false;
                }

                // Create defensive copy of cookie
                byte[] cookieBytes = new byte[256];
                System.Buffer.BlockCopy(cookieTlv.Value, 0, cookieBytes, 0, 256);

                // Extract BOS host (UTF-8 string)
                string bosHost = Encoding.UTF8.GetString(bosHostTlv.Value, 0, bosHostTlv.Value.Length);
                Debug.WriteLine($"[Redirect] BOS Host: {bosHost}");
                Debug.WriteLine($"[Redirect] Cookie (first 32 bytes): {BitConverter.ToString(cookieBytes, 0, 32)}...");

                return await ConnectToBosAsync(bosHost, cookieBytes, statusCode);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Redirect ERROR] {ex.Message}");
                return false;
            }
        }


        private byte[] TrimNullBytes(byte[] input)
        {
            int start = 0;
            while (start < input.Length && input[start] == 0)
                start++;

            int end = input.Length - 1;
            while (end >= 0 && input[end] == 0)
                end--;

            if (start > end)
                return new byte[0];

            byte[] result = new byte[end - start + 1];
            System.Buffer.BlockCopy(input, start, result, 0, result.Length);
            return result;
        }

        // Реальный лимит канала 1, который согласовал сервер (заполняется из
        // SNAC(04,05) в ParseIcbmParams). Если сервер ещё не ответил — считаем
        // это неизвестным и подстраховываемся консервативным значением.
        private int GetEffectiveIcbmByteBudget()
        {
            int max = _icbmMaxSize > 0 ? _icbmMaxSize : 2000;

            // Запас на служебные поля SNAC/TLV вокруг текста: cookie(8) + channel(2)
            // + UIN(1+N) + заголовки TLV(0x0002)/фрагментов(0x05,0x01) + TLV(0x0006).
            const int overhead = 96;
            return Math.Max(200, max - overhead);
        }

        // Режем текст на части по границе UTF-16 code unit'ов, не разрывая
        // суррогатные пары (эмодзи и т.п.), чтобы каждая часть укладывалась
        // в реальный лимит сервера.
        private static List<string> SplitTextForIcbm(string text, int maxBytes)
        {
            var chunks = new List<string>();
            int maxChars = Math.Max(1, maxBytes / 2); // BigEndianUnicode = 2 байта на code unit

            int pos = 0;
            while (pos < text.Length)
            {
                int len = Math.Min(maxChars, text.Length - pos);
                if (pos + len < text.Length && char.IsHighSurrogate(text[pos + len - 1]))
                    len--;
                if (len <= 0) len = 1;

                chunks.Add(text.Substring(pos, len));
                pos += len;
            }
            return chunks;
        }

        public async Task SendIcbmAsync(string toUin, string text)
        {
            if (!IsConnected) throw new Exception("Нет подключения к серверу");
            if (string.IsNullOrEmpty(text)) return;

            int budget = GetEffectiveIcbmByteBudget();
            int totalBytes = Encoding.BigEndianUnicode.GetByteCount(text);

            if (totalBytes <= budget)
            {
                await SendSingleIcbmAsync(toUin, text);
                return;
            }

            Debug.WriteLine("[ICBM] Сообщение (" + totalBytes + " байт) превышает лимит сервера (" +
                             budget + " байт) — разбиваю на части");

            var chunks = SplitTextForIcbm(text, budget);
            foreach (var chunk in chunks)
            {
                await SendSingleIcbmAsync(toUin, chunk);
                await Task.Delay(150); // небольшая пауза между частями, чтобы не словить rate limit
            }
        }

        private async Task SendSingleIcbmAsync(string toUin, string text)
        {
            Debug.WriteLine("[ICBM] Sending to " + toUin + " (" + text.Length + " chars)");

            byte[] msgBytes = Encoding.BigEndianUnicode.GetBytes(text);
            Debug.WriteLine("[ICBM] Encoded: " + msgBytes.Length + " bytes UTF-16BE");

            using (var ms = new MemoryStream())
            {
                // === 8 байт cookie ===
                uint uptime = (uint)Environment.TickCount;
                uint rand = (uint)new Random().Next();
                WriteU32BE(ms, uptime);
                WriteU32BE(ms, rand);

                // === channel 1 (2 байта BE) ===
                WriteU16BE(ms, 0x0001);

                // === UIN ===
                byte[] uinBytes = Encoding.UTF8.GetBytes(toUin);
                ms.WriteByte((byte)uinBytes.Length);
                ms.Write(uinBytes, 0, uinBytes.Length);

                // === TLV(0x0002) — message data ===
                // Собираем содержимое TLV заранее чтобы знать длину
                using (var tlvMs = new MemoryStream())
                {
                    // Fragment 0x05: capabilities
                    // 05 01 [len_BE_2] [caps...]
                    // caps = { 0x01 } = text capability
                    byte[] caps = new byte[] { 0x01 };
                    tlvMs.WriteByte(0x05); // fragment id
                    tlvMs.WriteByte(0x01); // fragment version
                    WriteU16BEStream(tlvMs, (ushort)caps.Length);
                    tlvMs.Write(caps, 0, caps.Length);

                    // Fragment 0x01: text
                    // 01 01 [len_BE_2] [charset_BE_2] [lang_BE_2] [text...]
                    // len = 2 (charset) + 2 (lang) + msgBytes.Length
                    ushort textFragLen = (ushort)(2 + 2 + msgBytes.Length);
                    tlvMs.WriteByte(0x01); // fragment id
                    tlvMs.WriteByte(0x01); // fragment version
                    WriteU16BEStream(tlvMs, textFragLen);
                    WriteU16BEStream(tlvMs, 0x0002); // charset UTF-16 BE
                    WriteU16BEStream(tlvMs, 0xFFFF); // language
                    tlvMs.Write(msgBytes, 0, msgBytes.Length);

                    byte[] tlvData = tlvMs.ToArray();

                    // Пишем TLV(0x0002)
                    WriteU16BE(ms, 0x0002);
                    WriteU16BE(ms, (ushort)tlvData.Length);
                    ms.Write(tlvData, 0, tlvData.Length);
                }

                // === TLV(0x0006) — store if offline (пустой) ===
                WriteU16BE(ms, 0x0006);
                WriteU16BE(ms, 0x0000);

                byte[] payload = ms.ToArray();
                await SendSnacAsync(0x04, 0x06, 0x0000, GetNextRequestID(), payload);
                Debug.WriteLine("[ICBM] Sent OK, payload=" + payload.Length + " bytes");
            }
        }

        // Вспомогательные методы записи big-endian
        private void WriteU16BE(MemoryStream ms, ushort value)
        {
            ms.WriteByte((byte)(value >> 8));
            ms.WriteByte((byte)(value & 0xFF));
        }

        private void WriteU32BE(MemoryStream ms, uint value)
        {
            ms.WriteByte((byte)(value >> 24));
            ms.WriteByte((byte)(value >> 16));
            ms.WriteByte((byte)(value >> 8));
            ms.WriteByte((byte)(value & 0xFF));
        }

        private void WriteU16BEStream(MemoryStream ms, ushort value)
        {
            ms.WriteByte((byte)(value >> 8));
            ms.WriteByte((byte)(value & 0xFF));
        }


        private static string DecodeWin1251(byte[] data, int offset, int length)
        {
            // Таблица символов windows-1251 начиная с 0x80
            string high = "\u0402\u0403\u201A\u0453\u201E\u2026\u2020\u2021" +
                          "\u20AC\u2030\u0409\u2039\u040A\u040C\u040B\u040F" +
                          "\u0452\u2018\u2019\u201C\u201D\u2022\u2013\u2014" +
                          "\uFFFD\u2122\u0459\u203A\u045A\u045C\u045B\u045F" +
                          "\u00A0\u040E\u045E\u0408\u00A4\u0490\u00A6\u00A7" +
                          "\u0401\u00A9\u0404\u00AB\u00AC\u00AD\u00AE\u0407" +
                          "\u00B0\u00B1\u0406\u0456\u0491\u00B5\u00B6\u00B7" +
                          "\u0451\u2116\u0454\u00BB\u0458\u0405\u0455\u0457" +
                          "\u0410\u0411\u0412\u0413\u0414\u0415\u0416\u0417" +
                          "\u0418\u0419\u041A\u041B\u041C\u041D\u041E\u041F" +
                          "\u0420\u0421\u0422\u0423\u0424\u0425\u0426\u0427" +
                          "\u0428\u0429\u042A\u042B\u042C\u042D\u042E\u042F" +
                          "\u0430\u0431\u0432\u0433\u0434\u0435\u0436\u0437" +
                          "\u0438\u0439\u043A\u043B\u043C\u043D\u043E\u043F" +
                          "\u0440\u0441\u0442\u0443\u0444\u0445\u0446\u0447" +
                          "\u0448\u0449\u044A\u044B\u044C\u044D\u044E\u044F";

            var sb = new System.Text.StringBuilder(length);
            for (int i = 0; i < length; i++)
            {
                byte b = data[offset + i];
                if (b < 0x80)
                    sb.Append((char)b);
                else
                    sb.Append(high[b - 0x80]);
            }
            return sb.ToString();
        }

        public async Task<bool> WaitForRedirectOrBosAsync(uint statusCode)
        {
            StatusUpdater?.Invoke("Ждем redirect...");
            Debug.WriteLine("[Login] Waiting for redirect or BOS connect...");

            while (true)
            {
                var flap = await ReceiveFlapWithTimeout(TimeSpan.FromSeconds(5));
                if (flap == null)
                {
                    Debug.WriteLine("[Login] No FLAP response");
                    return false;
                }

                if (flap.Channel == 0x04)
                {
                    StatusUpdater?.Invoke("Получили redirect...");
                    Debug.WriteLine($"[Login] Got redirect FLAP (0x04), Length: {flap.Data.Length}");
                    return await HandleBosRedirectAsync(flap.Data, statusCode);
                }

                Debug.WriteLine($"[Login] Ignoring unexpected FLAP type: 0x{flap.Channel:X2}");
            }
        }

        private async Task ShowMessageDialog(string message)
        {
            Debug.WriteLine($"[Dialog] Подготовка к показу: {message}");

            // Получаем глобальный диспетчер главного окна
            var dispatcher = Windows.ApplicationModel.Core.CoreApplication.MainView.CoreWindow.Dispatcher;

            await dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, async () =>
            {
                try
                {
                    Debug.WriteLine("[Dialog] Поток UI успешно захвачен. Создаем ContentDialog...");

                    var dialog = new Windows.UI.Xaml.Controls.ContentDialog
                    {
                        Title = "Ошибка",
                        Content = message,
                        CloseButtonText = "ОК"
                    };

                    await dialog.ShowAsync();

                    Debug.WriteLine("[Dialog] Окно успешно отображено.");
                }
                catch (Exception ex)
                {
                    // ЕСЛИ ОКНО НЕ ПОЯВИТСЯ, ЭТА ОШИБКА БУДЕТ В ЛОГАХ
                    Debug.WriteLine($"[Dialog CRITICAL ERROR] Ошибка при показе окна: {ex}");
                }
            });
        }


        public async Task<bool> AuthenticateAndInitializeAsync(string nickname, uint statusCode)
        {
            if (!await AuthenticateAsync(statusCode))
                return false;

            if (!await WaitForRedirectOrBosAsync(statusCode))
                return false;

            await InitializeOscarSessionAsync(statusCode);
            return true;
        }

        public async Task SendCapabilitiesAsync()
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                // TLV 0x0006: user class/status
                writer.Write(SwapUInt16(0x0006)); // TLV type
                writer.Write(SwapUInt16(0x0004)); // Length
                writer.Write(SwapUInt32(0x00000000)); // Online + Normal class

                // TLV 0x000C: Capabilities block (GUIDs)
                byte[] caps = new byte[]
                {
            // Standard ICQ client capabilities
            0x09, 0x46, 0x13, 0x4C, 0x4B, 0xE2, 0x4C, 0x7F,
            0xBB, 0xF8, 0x3F, 0xC3, 0xD6, 0xE7, 0x09, 0x32 // Basic messaging
                };

                writer.Write(SwapUInt16(0x000C));
                writer.Write(SwapUInt16((ushort)caps.Length));
                writer.Write(caps);

                byte[] data = ms.ToArray();
                await SendSnacAsync(0x0001, 0x000E, 0x0000, 0x0000, data);

                Debug.WriteLine("[Capabilities] Sent user info with basic capability block");
            }
        }

        private void HandleMetaResponse(byte[] data)
        {
            try
            {
                var results = new List<SearchResult>();
                bool isLast = false;

                int offset = 0;
                while (offset + 4 <= data.Length)
                {
                    ushort tlvType = ReadU16(data, ref offset);
                    ushort tlvLen = ReadU16(data, ref offset);
                    if (offset + tlvLen > data.Length) break;

                    if (tlvType == 0x0001)
                    {
                        // Используем расширенный парсер
                        HandleMetaResponseExtended(data, offset, tlvLen, results, out isLast);
                    }
                    offset += tlvLen;
                }

                if (results.Count > 0 || isLast)
                {
                    if (SearchResultReceived != null)
                        SearchResultReceived(results, isLast);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[HandleMetaResponse ERROR] " + ex.Message);
            }
        }



        private async void HandleIncomingIcbm(byte[] data)
        {
            try
            {
                Debug.WriteLine("Raw ICBM: " + BitConverter.ToString(data));
                int offset = 0;

                // skip 8 bytes cookie
                offset += 8;

                if (offset + 2 > data.Length) return;
                ushort channel = ReadU16(data, ref offset);

                if (offset + 1 > data.Length) return;
                byte uinLen = data[offset++];
                if (offset + uinLen > data.Length) return;
                string senderUin = Encoding.UTF8.GetString(data, offset, uinLen);
                offset += uinLen;

                // warning level
                if (offset + 2 > data.Length) return;
                offset += 2;

                // пропускаем фиксированные TLV
                if (offset + 2 > data.Length) return;
                ushort tlvCount = ReadU16(data, ref offset);
                for (int i = 0; i < tlvCount && offset + 4 <= data.Length; i++)
                {
                    int peekOffset = offset + 2;
                    ushort tlvLen = ReadU16(data, ref peekOffset);
                    offset += 4 + tlvLen;
                }

                string text = null;

                if (channel == 0x0001)
                {
                    while (offset + 4 <= data.Length)
                    {
                        ushort tlvType = ReadU16(data, ref offset);
                        ushort tlvLen = ReadU16(data, ref offset);
                        int tlvEnd = offset + tlvLen;
                        if (tlvEnd > data.Length) break;

                        if (tlvType == 0x0002)
                        {
                            int moff = offset;

                            // fragment 0x05 — capabilities: пропускаем
                            if (moff + 4 > tlvEnd) { offset = tlvEnd; break; }
                            if (data[moff] == 0x05)
                            {
                                moff += 2; // id + version
                                ushort capLen = (ushort)((data[moff] << 8) | data[moff + 1]);
                                moff += 2 + capLen;
                            }

                            // fragment 0x01 — text
                            if (moff + 4 <= tlvEnd && data[moff] == 0x01)
                            {
                                moff += 2; // id + version
                                ushort textBlockLen = (ushort)((data[moff] << 8) | data[moff + 1]);
                                moff += 2;

                                if (textBlockLen >= 4 && moff + textBlockLen <= tlvEnd)
                                {
                                    // читаем charset
                                    ushort charset = (ushort)((data[moff] << 8) | data[moff + 1]);
                                    moff += 4; // charset + lang

                                    int textLen = textBlockLen - 4;
                                    if (textLen > 0)
                                    {
                                        // charset 0x0002 = UTF-16 BE, иначе Windows-1251
                                        if (charset == 0x0002)
                                            text = Encoding.BigEndianUnicode.GetString(data, moff, textLen);
                                        else
                                            text = charset == 0x0002
    ? Encoding.BigEndianUnicode.GetString(data, moff, textLen)
    : DecodeWin1251(data, moff, textLen);
                                    }
                                }
                            }
                            offset = tlvEnd;
                            break;
                        }
                        else
                        {
                            offset = tlvEnd;
                        }
                    }
                }
                else if (channel == 0x0004)
                {
                    while (offset + 4 <= data.Length)
                    {
                        ushort tlvType = ReadU16(data, ref offset);
                        ushort tlvLen = ReadU16(data, ref offset);
                        int tlvEnd = offset + tlvLen;
                        if (tlvEnd > data.Length) break;

                        if (tlvType == 0x0005 && tlvLen > 8)
                        {
                            int moff = offset;
                            moff += 4; // sender uin LE
                            byte msgType = data[moff++];
                            byte msgFlags = data[moff++];
                            // длина в LE
                            ushort msgLen = (ushort)(data[moff] | (data[moff + 1] << 8));
                            moff += 2;

                            if (msgLen > 0 && moff + msgLen <= tlvEnd)
                            {
                                // channel 4 всегда Windows-1251, null-terminated
                                int len = msgLen;
                                if (len > 0 && data[moff + len - 1] == 0x00) len--;
                                if (len > 0)
                                    text = DecodeWin1251(data, moff, len);
                            }
                            offset = tlvEnd;
                            break;
                        }
                        else
                        {
                            offset = tlvEnd;
                        }
                    }
                }

                else if (channel == 0x0002)
                {
                    // Channel 2 — ищем TLV(0x0005) rendezvous data
                    while (offset + 4 <= data.Length)
                    {
                        ushort tlvType = ReadU16(data, ref offset);
                        ushort tlvLen = ReadU16(data, ref offset);
                        int tlvEnd = offset + tlvLen;
                        if (tlvEnd > data.Length) break;

                        if (tlvType == 0x0005)
                        {
                            // Внутри TLV(0x0005): msgType(2) + cookie(8) + capability(16) + TLVs
                            int inner = offset;
                            inner += 2;  // msgType
                            inner += 8;  // cookie
                            inner += 16; // capability GUID

                            // Парсим вложенные TLV
                            while (inner + 4 <= tlvEnd)
                            {
                                ushort it = ReadU16(data, ref inner);
                                ushort il = ReadU16(data, ref inner);
                                int ie = inner + il;
                                if (ie > tlvEnd) break;

                                if (it == 0x2711 && il > 0)
                                {
                                    text = ParseChannel2ExtData(data, inner, il);
                                    Debug.WriteLine("[ICBM ch2] Parsed text: " + text);
                                }
                                inner = ie;
                            }
                        }
                        offset = tlvEnd;
                        if (text != null) break;
                    }
                }

                if (text != null)
                {
                    if (contacts != null && !contacts.Any(c => c.Uin == senderUin))
                    {
                        var tempContact = new Contact
                        {
                            Uin = senderUin,
                            Name = senderUin, // имя = UIN пока не известно
                            GroupId = 0,
                            ItemId = 0,
                            Group = "",
                            StatusIcon = "/Assets/statuses/nicl.png",
                            IsTemporary = true // новое поле
                        };

                        await _dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                        {
                            contacts.Add(tempContact);
                            if (TemporaryContactAdded != null)
                                TemporaryContactAdded(tempContact);
                            Debug.WriteLine("[ICBM] Added temporary contact: " + senderUin);
                        });

                        if (ContactStatusChanged != null) ContactStatusChanged();
                    }
                    // Сохраняем в очередь
                    if (!_pendingMessages.ContainsKey(senderUin))
                        _pendingMessages[senderUin] = new List<string[]>();
                    _pendingMessages[senderUin].Add(new string[]
                    {
        text,
        DateTime.Now.ToString("HH:mm")
                    });

                    IncomingMessage?.Invoke(senderUin, text);
                    SoundService.PlayMessage();

                    string displayName = senderUin;
                    if (contacts != null)
                    {
                        var c = contacts.FirstOrDefault(x => x.Uin == senderUin);
                        if (c != null) displayName = c.Name;
                    }
                    var ignored = NotificationService.Instance.OnMessageReceived(
                        senderUin, displayName, text, _dispatcher);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HandleIncomingIcbm ERROR] {ex}");
            }
        }

        private string ParseChannel2ExtData(byte[] data, int offset, int len)
        {
            try
            {
                int end = offset + len;

                // 1. Читаем первый блок (Chunk 1) - там лежат GUID плагина и capabilities
                if (offset + 2 > end) return null;
                ushort chunk1Len = ReadU16LE(data, ref offset);

                // Пропускаем содержимое первого блока
                if (offset + chunk1Len > end) return null;
                offset += chunk1Len;

                // 2. Читаем второй блок (Chunk 2) - служебные счетчики
                if (offset + 2 > end) return null;
                ushort chunk2Len = ReadU16LE(data, ref offset);

                // Пропускаем содержимое второго блока
                if (offset + chunk2Len > end) return null;
                offset += chunk2Len;

                // 3. Теперь начинается сам блок сообщения
                // Проверяем, что есть как минимум 8 байт для заголовка: 
                // type(1) + flags(1) + status(2) + priority(2) + msgLen(2)
                if (offset + 8 > end) return null;

                byte msgType = data[offset++];
                byte msgFlags = data[offset++];
                ushort statusCode = ReadU16LE(data, ref offset);
                ushort priorityCode = ReadU16LE(data, ref offset);
                ushort msgLen = ReadU16LE(data, ref offset);

                if (msgLen == 0) return "";

                // Защита от «кривых» клиентов, указывающих размер больше реального
                if (offset + msgLen > end)
                {
                    msgLen = (ushort)(end - offset);
                }

                // 4. Убираем null-терминаторы в конце строки (0x00)
                int textLen = msgLen;
                while (textLen > 0 && (data[offset + textLen - 1] == 0x00 || data[offset + textLen - 1] == 0xFF))
                {
                    textLen--;
                }

                if (textLen == 0) return "";

                // 5. Декодируем текст
                // Для Channel 2 в 99% случаев используется локальная кодировка (Win-1251)
                string text = Encoding.UTF8.GetString(data, offset, textLen);

                Debug.WriteLine("[ICBM ch2] Parsed text: " + text);
                return text;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[ParseChannel2ExtData ERROR] " + ex);
                return null;
            }
        }

        public List<string[]> GetAndClearPending(string uin)
        {
            if (!_pendingMessages.ContainsKey(uin))
                return new List<string[]>();
            var msgs = _pendingMessages[uin];
            _pendingMessages[uin] = new List<string[]>();
            return msgs;
        }

        public async Task<UserBasicInfo> RequestFullUserInfoAsync(string uin, ushort seq)
        {
            uint uinNum = uint.Parse(uin);
            var tcs = new TaskCompletionSource<UserBasicInfo>();
            var info = new UserBasicInfo();

            Action<UserBasicInfo> handler = null;
            handler = (receivedInfo) =>
            {
                OwnInfoReceived -= handler;
                tcs.TrySetResult(receivedInfo);
            };
            OwnInfoReceived += handler;

            // Таймаут 10 секунд
            Task.Delay(10000).ContinueWith(_ =>
            {
                OwnInfoReceived -= handler;
                tcs.TrySetResult(null);
            });

            // Отправляем SNAC(15,02)/07D0/04B2
            using (var body = new MemoryStream())
            {
                WriteU32LE(body, uinNum); // uin to search (LE)
                byte[] payload = BuildMetaRequest(0x04B2, seq, body.ToArray());
                await SendSnacAsync(0x15, 0x02, 0x0001, GetNextRequestID(), payload);
                Debug.WriteLine("[UserInfo] Sent full info request for " + uin);
            }

            return await tcs.Task;
        }

        // ── Обработка ответа META_BASIC_USERINFO (0x00C8) ──────────────────
        private void HandleMetaBasicUserInfo(byte[] data, int offset, int end)
        {
            try
            {
                if (offset + 1 > end) return;
                byte success = data[offset++];
                if (success != 0x0A)
                {
                    Debug.WriteLine("[UserInfo] Error response: " + success.ToString("X2"));
                    if (OwnInfoReceived != null) OwnInfoReceived(null);
                    return;
                }

                var info = new UserBasicInfo();
                info.Nick = ReadAsciizLE(data, ref offset, end);
                info.FirstName = ReadAsciizLE(data, ref offset, end);
                info.LastName = ReadAsciizLE(data, ref offset, end);
                info.Email = ReadAsciizLE(data, ref offset, end);
                info.City = ReadAsciizLE(data, ref offset, end);
                info.State = ReadAsciizLE(data, ref offset, end);
                info.HomePhone = ReadAsciizLE(data, ref offset, end);
                info.HomeFax = ReadAsciizLE(data, ref offset, end);
                info.Address = ReadAsciizLE(data, ref offset, end);
                info.CellPhone = ReadAsciizLE(data, ref offset, end);
                info.ZipCode = ReadAsciizLE(data, ref offset, end);

                if (offset + 2 <= end) info.Country = ReadU16LE(data, ref offset);
                if (offset + 1 <= end) info.GmtOffset = data[offset++];
                if (offset + 1 <= end) info.AuthFlag = data[offset++];
                if (offset + 1 <= end) info.WebAware = data[offset++];

                Debug.WriteLine("[UserInfo] Got basic info: " + info.Nick + " " + info.FirstName);

                if (OwnInfoReceived != null) OwnInfoReceived(info);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[HandleMetaBasicUserInfo ERROR] " + ex.Message);
                if (OwnInfoReceived != null) OwnInfoReceived(null);
            }
        }

        // ── Установка базовой информации ────────────────────────────────────
        public async Task<bool> SetBasicUserInfoAsync(UserBasicInfo info, ushort seq)
        {
            var tcs = new TaskCompletionSource<bool>();
            Action<List<SearchResult>, bool> dummy = null; // заглушка

            // Используем _ssiAckHandler для ожидания ответа 0x0064
            var innerTcs = new TaskCompletionSource<bool>();
            _metaSaveResultHandler = (success) =>
            {
                _metaSaveResultHandler = null;
                innerTcs.TrySetResult(success);
            };

            Task.Delay(10000).ContinueWith(_ => innerTcs.TrySetResult(false));

            using (var body = new MemoryStream())
            {
                WriteAsciiz(body, info.Nick ?? "");
                WriteAsciiz(body, info.FirstName ?? "");
                WriteAsciiz(body, info.LastName ?? "");
                WriteAsciiz(body, info.Email ?? "");
                WriteAsciiz(body, info.City ?? "");
                WriteAsciiz(body, info.State ?? "");
                WriteAsciiz(body, info.HomePhone ?? "");
                WriteAsciiz(body, info.HomeFax ?? "");
                WriteAsciiz(body, info.Address ?? "");
                WriteAsciiz(body, info.CellPhone ?? "");
                WriteAsciiz(body, info.ZipCode ?? "");
                WriteU16LE(body, info.Country);
                body.WriteByte(info.GmtOffset);
                body.WriteByte(info.WebAware);

                byte[] payload = BuildMetaRequest(0x03EA, seq, body.ToArray());
                await SendSnacAsync(0x15, 0x02, 0x0001, GetNextRequestID(), payload);
                Debug.WriteLine("[UserInfo] Sent SetBasicUserInfo");
            }

            return await innerTcs.Task;
        }

        // Поле для обработчика результата сохранения
        private Action<bool> _metaSaveResultHandler;
        private TaskCompletionSource<bool> _deleteAccountTcs;
        private readonly object _deleteLock = new object();
        private volatile bool _isDeleting = false;
        public bool IsDeleting => _isDeleting;

        // ── Обновить HandleMetaResponse ─────────────────────────────────────
        // В существующем HandleMetaResponse добавь обработку новых subtypes:
        private void HandleMetaResponseExtended(byte[] data, int start, int len,
            List<SearchResult> results, out bool isLast)
        {
            isLast = false;
            int offset = start;
            int end = start + len;

            if (offset + 10 > end) return;
            offset += 2; // chunk size
            offset += 4; // owner uin
            offset += 2; // data type (0x07DA)
            offset += 2; // sequence

            if (offset + 2 > end) return;
            ushort subtype = ReadU16LE(data, ref offset);

            Debug.WriteLine("[META Reply] subtype=0x" + subtype.ToString("X4"));

            switch (subtype)
            {
                case 0x00C8: // META_BASIC_USERINFO
                    ParseFullUserInfoBasic(data, offset, end);
                    isLast = true;
                    break;

                case 0x0064: // Save result
                    {
                        if (offset + 1 <= end)
                        {
                            byte success = data[offset];
                            bool ok = success == 0x0A;
                            Debug.WriteLine("[META] Save result: " + (ok ? "OK" : "Error " + success.ToString("X2")));
                            if (_metaSaveResultHandler != null)
                                _metaSaveResultHandler(ok);
                        }
                        isLast = true;
                        break;
                    }

                case 0x01AE: // Search result last
                    isLast = true;
                    if (offset + 1 <= end && data[offset++] == 0x0A)
                    {
                        var r = ParseSearchRecord(data, ref offset, end);
                        if (r != null) results.Add(r);
                    }
                    break;

                case 0x01A4: // Search result
                    if (offset + 1 <= end && data[offset++] == 0x0A)
                    {
                        var r = ParseSearchRecord(data, ref offset, end);
                        if (r != null) results.Add(r);
                    }
                    break;

                case 0x00B4: // META_UNREGISTER_ACK — SNAC(15,03)/07DA/00B4
                    {
                        isLast = true;
                        bool ok = false;
                        if (offset < end)
                        {
                            byte successByte = data[offset];
                            ok = successByte == 0x0A;
                            Debug.WriteLine("[META] UNREGISTER_ACK successByte=0x" + successByte.ToString("X2") + " ok=" + ok);
                        }
                        CompleteDeleteAccount(ok);
                        break;
                    }

            }
        }


        // Jasmine-совместимый SetStatusAsync (SNAC 01,1E, TLV 0x0006 = flags WORD + status WORD)
        public async Task SetStatusAsync(uint statusCode)
        {
            await SendSetStatusAsync(statusCode);
        }


        private void HandleTypingNotification(byte[] data)
        {
            try
            {
                int offset = 0;
                offset += 8; // cookie
                offset += 2; // channel

                if (offset + 1 > data.Length) return;
                byte uinLen = data[offset++];
                if (offset + uinLen > data.Length) return;
                string uin = Encoding.UTF8.GetString(data, offset, uinLen);
                offset += uinLen;

                if (offset + 2 > data.Length) return;
                ushort type = ReadU16(data, ref offset);

                Debug.WriteLine("[Typing] From=" + uin + " type=" + type);
                if (TypingNotificationReceived != null)
                    TypingNotificationReceived(uin, type);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[Typing ERROR] " + ex.Message);
            }
        }

        private async Task ReceiveLoopAsync()
        {
            while (true)
            {
                var flap = await ReceiveFlapWithTimeout(TimeSpan.FromSeconds(30));
                if (flap == null)
                    continue;

                // Разбор FLAP/SNAC и вызов нужных обработчиков
                await HandleFlapAsync(flap);
            }
        }

        private async Task HandleFlapAsync(FlapFrame flap)
        {
            if (flap.Channel != 0x02 || flap.Data.Length < 10)
                return;

            var snac = SnacPacket.Parse(flap.Data);
            if (snac == null)
                return;

            Debug.WriteLine($"[SNAC] Received: 0x{snac.Family:X4}/0x{snac.Subtype:X4}, " +
                           $"Flags=0x{snac.Flags:X4}, ReqId=0x{snac.RequestId:X8}");

            // Check SNAC flags
            bool moreData = (snac.Flags & 0x0001) != 0; // More data to come
            bool serverBusy = (snac.Flags & 0x0002) != 0; // Server is busy
            bool error = (snac.Flags & 0x8000) != 0; // Error response

            if (error)
            {
                Debug.WriteLine($"[SNAC ERROR] Error in response for 0x{snac.Family:X4}/0x{snac.Subtype:X4}");
                // Handle error (usually error code is first 2 bytes of Data)
                if (snac.Data.Length >= 2)
                {
                    ushort errorCode = (ushort)((snac.Data[0] << 8) | snac.Data[1]);
                    Debug.WriteLine($"[SNAC ERROR] Error code: 0x{errorCode:X4}");
                }
            }

            // Handle specific SNAC types
            switch (snac.Family)
            {
                case 0x0001:
                    switch (snac.Subtype)
                    {
                        case 0x0003:
                            Debug.WriteLine("[SNAC] Service families list");
                            var families = ParseSupportedFamilies(snac.Data);
                            await HandleServiceFamilies(families);
                            break;
                        case 0x0018:
                            Debug.WriteLine("[SNAC] Service versions reply");
                            await HandleServiceVersionsResponse(snac.Data);
                            break;
                    }
                    break;

                case 0x0002:
                    switch (snac.Subtype)
                    {
                        case 0x0006: // SRV_USER_INFO_UPDATE (ответ на наш запрос 02,05)
                            await HandleUserInfoReply(snac.Data);
                            break;
                    }
                    break;

                case 0x0003:
                    switch (snac.Subtype)
                    {
                        case 0x000B:
                            Debug.WriteLine("[SNAC] User online");
                            await HandleUserOnlineAsync(snac.Data);
                            break;
                        case 0x000C:
                            Debug.WriteLine("[SNAC] User offline");
                            await HandleUserOfflineAsync(snac.Data);
                            break;
                    }
                    break;

                case 0x0004: // ICBM
                    switch (snac.Subtype)
                    {
                        case 0x0005: // ICBM params response
                            ParseIcbmParams(snac.Data);
                            break;
                        case 0x0007:
                            HandleIncomingIcbm(snac.Data);
                            break;
                        case 0x000A: // missed message
                            HandleMissedMessage(snac.Data);
                            break;
                        case 0x0014: // typing notification
                            HandleTypingNotification(snac.Data);
                            break;
                    }
                    break;
                case 0x0015:
                    switch (snac.Subtype)
                    {
                        case 0x0003:
                            Debug.WriteLine("[Search] Got META response, parsing...");
                            HandleMetaResponse(snac.Data);
                            break;
                    }
                    break;
                case 0x0013:
                    switch (snac.Subtype)
                    {
                        case 0x0006: // contact list
                                     // уже обрабатывается в InitServicesAsync
                            break;
                        case 0x000E: // SSI ack
                            Debug.WriteLine("[SSI] Got SNAC(13,0E)");
                            if (_ssiAckHandler != null)
                            {
                                int aoff = 0;
                                ushort result = snac.Data.Length >= 2
                                    ? ReadU16(snac.Data, ref aoff)
                                    : (ushort)0xFFFF;
                                var handler = _ssiAckHandler;
                                _ssiAckHandler = null;
                                handler(result);
                            }
                            break;
                        case 0x000F: // SSI edit ack
                        case 0x0010:
                            break;
                    }
                    break;
            }
        }

        private Task<ushort> WaitForSsiAck()
        {
            var tcs = new TaskCompletionSource<ushort>();

            _ssiAckHandler = (result) =>
            {
                tcs.TrySetResult(result);
            };

            // Таймаут 10 секунд
            Task.Delay(10000).ContinueWith(_ =>
                tcs.TrySetResult(0xFFFF));

            return tcs.Task;
        }

        public async Task SendTypingNotificationAsync(string toUin, ushort notificationType)
        {
            if (!IsConnected) return;
            // notificationType: 0x0002 = начал, 0x0001 = набрал, 0x0000 = остановился
            try
            {
                byte[] uinBytes = Encoding.UTF8.GetBytes(toUin);
                using (var ms = new MemoryStream())
                {
                    // cookie 8 байт нулей
                    WriteU32BE(ms, 0x00000000);
                    WriteU32BE(ms, 0x00000000);

                    WriteU16BE(ms, 0x0001); // channel 1
                    ms.WriteByte((byte)uinBytes.Length);
                    ms.Write(uinBytes, 0, uinBytes.Length);
                    WriteU16BE(ms, notificationType);

                    await SendSnacAsync(0x04, 0x14, 0x0000, GetNextRequestID(), ms.ToArray());
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[Typing] Send error: " + ex.Message);
            }
        }


        private async Task HandleUserInfoReply(byte[] data)
        {
            try
            {
                int offset = 0;
                if (offset + 1 > data.Length) return;
                byte uinLen = data[offset++];
                if (offset + uinLen > data.Length) return;
                string uin = Encoding.UTF8.GetString(data, offset, uinLen);
                offset += uinLen;

                if (offset + 2 > data.Length) return;
                offset += 2; // warning level

                if (offset + 2 > data.Length) return;
                ushort tlvCount = ReadU16(data, ref offset);

                uint status = 0;
                int fixedTLVEnd = -1;
                for (int i = 0; i < tlvCount && offset + 4 <= data.Length; i++)
                {
                    ushort tlvType = ReadU16(data, ref offset);
                    ushort tlvLen = ReadU16(data, ref offset);
                    int tlvEnd = offset + tlvLen;
                    if (tlvEnd > data.Length) break;

                    if (tlvType == 0x0006 && tlvLen >= 4)
                    {
                        status = ReadU32(data, ref offset);
                    }
                    // остальные TLV fixed part пропускаем — нас интересует
                    // только базовый статус отсюда; capabilities и away msg
                    // лежат в dependent part (после всех fixed TLV).

                    offset = tlvEnd;
                    fixedTLVEnd = tlvEnd;
                }

                Debug.WriteLine("[Location] Info reply for " + uin +
                                " status=0x" + status.ToString("X8") +
                                " dataLen=" + data.Length + " fixedEnd=" + fixedTLVEnd);

                // ── Dependent part ─────────────────────────────────────
                // Документация говорит, что dependent part идёт ПОСЛЕ
                // фиксированного списка TLV, и каждый dependent TLV имеет
                // обычный заголовок (type word + length word). Количество
                // не объявлено — читаем пока не кончатся данные.
                //
                // Нас интересуют:
                //   TLV(0x0002) — профиль (type=0x0001 запрос)
                //   TLV(0x0003) — кодировка away (type=0x0003 запрос)
                //   TLV(0x0004) — текст away-сообщения (type=0x0003 запрос)
                //   TLV(0x0005) — список capabilities CLSID'ов (type=0x0004 запрос)
                string awayText = null;
                string[] caps = null;

                while (offset + 4 <= data.Length)
                {
                    ushort depType = ReadU16(data, ref offset);
                    ushort depLen = ReadU16(data, ref offset);
                    if (offset + depLen > data.Length) break;

                    switch (depType)
                    {
                        // TLV(0x0002) — client profile (UTF-8, длина-prefix word)
                        case 0x0002:
                            if (depLen >= 2)
                            {
                                ushort sLen = (ushort)((data[offset] << 8) | data[offset + 1]);
                                int sStart = offset + 2;
                                if (sLen > 0 && sStart + sLen <= offset + depLen)
                                {
                                    string profile = Encoding.UTF8.GetString(data, sStart, sLen);
                                    Debug.WriteLine("[Location] " + uin + " profile=\"" +
                                                    (profile.Length > 80 ? profile.Substring(0, 80) + "..." : profile) + "\"");
                                }
                            }
                            break;

                        // TLV(0x0004) — away message text (UTF-8, длина-prefix word)
                        case 0x0004:
                            if (depLen >= 2)
                            {
                                ushort sLen = (ushort)((data[offset] << 8) | data[offset + 1]);
                                int sStart = offset + 2;
                                if (sLen > 0 && sStart + sLen <= offset + depLen)
                                {
                                    awayText = Encoding.UTF8.GetString(data, sStart, sLen);
                                    Debug.WriteLine("[Location] " + uin + " away=\"" +
                                                    (awayText.Length > 80 ? awayText.Substring(0, 80) + "..." : awayText) + "\"");
                                }
                            }
                            break;

                        // TLV(0x0005) — user capabilities. Это то, ради чего
                        // затевался весь запрос type=0x0004. Список 16-байтных
                        // CLSID'ов; среди них могут быть QIP- и X-Status-ы.
                        case 0x0005:
                            {
                                int capCount = depLen / 16;
                                var capList = new List<string>(capCount);
                                for (int c = 0; c < capCount; c++)
                                {
                                    int coff = offset + c * 16;
                                    var sb = new StringBuilder(32);
                                    for (int b = 0; b < 16; b++)
                                        sb.Append(data[coff + b].ToString("X2"));
                                    capList.Add(sb.ToString());
                                }
                                caps = capList.ToArray();
                                Debug.WriteLine("[Location] " + uin + " capabilities (" +
                                                capList.Count + "): " +
                                                string.Join(",", capList));
                            }
                            break;
                    }

                    offset += depLen;
                }

                // ── Применяем результат к контакту ───────────────────────
                // Тут два пути:
                //   1) capabilities пришли (caps != null) — прогоняем
                //      через QIP/X-Status-таблицы, обновляем кэш и иконку.
                //   2) пришёл away text — пишем в info.StatusMessage.
                //   3) пришёл только базовый статус — старая логика, как
                //      было до этого изменения.

                await _dispatcher.RunAsync(CoreDispatcherPriority.Normal, async () =>
                 {
                     if (contacts == null) return;
                     var contact = contacts.FirstOrDefault(c => c.Uin == uin);
                     if (contact == null) return;

                    // Сохраняем away text если был
                    if (awayText != null && contact.Info != null)
                         contact.Info.StatusMessage = awayText;

                    // Применяем capabilities если пришли
                    if (caps != null)
                     {
                        // Сохранять в кэш capabilities больше не нужно —
                        // при следующем SNAC(03,0B) мы снова отправим
                        // SNAC(02,05) type=0x0004, так что сервер всегда
                        // сообщит актуальный QIP-режим.

                        if (contact.Info != null)
                             contact.Info.Capabilities = caps;

                        // Проверяем QIP-режим
                        uint finalStatus = status;
                         int qipId = 0;
                         string xtrazIcon = null;
                         int xStatusId = 0;
                         string xStatusTitle = null;
                         string xStatusDesc = null;

                         foreach (var guidHex in caps)
                         {
                             uint? qipCode = QipStatusCodes.FromGuid(guidHex);
                             if (qipCode.HasValue)
                             {
                                 finalStatus = qipCode.Value;
                                 qipId = (int)qipCode.Value;
                                 Debug.WriteLine("[Location] " + uin +
                                                 " QIP-status из 02,06: 0x" +
                                                 finalStatus.ToString("X8") +
                                                 " (" + (QipStatusCodes.GetName(finalStatus) ?? "?") + ")");
                             }

                             int? xid = XStatusCodes.FromGuid(guidHex);
                             if (xid.HasValue)
                             {
                                 xStatusId = xid.Value;
                                 xtrazIcon = guidHex;
                                 var xi = XStatusCodes.GetInfo(xid.Value);
                                 if (xi != null)
                                 {
                                     xStatusTitle = xi.Title;
                                     xStatusDesc = xi.Description;
                                 }
                             }
                         }

                         contact.StatusIcon = StatusIconHelper.GetIconForStatus(finalStatus);
                         if (xtrazIcon != null)
                             contact.XtrazIcon = xtrazIcon;
                         else if (xStatusId == 0)
                             contact.XtrazIcon = null;

                         if (contact.Info != null)
                         {
                             contact.Info.Status = finalStatus;
                             contact.Info.QipStatus = finalStatus;
                             contact.Info.XStatusId = xStatusId;
                             contact.Info.XStatusTitle = xStatusTitle;
                             contact.Info.XStatusDescription = xStatusDesc;
                         }
                     }
                     else if (status != 0)
                     {
                         // Capabilities не пришли — применяем базовый OSCAR статус
                         // как fallback. QIP-иконку не трогаем если она уже стоит.
                         string baseIcon = StatusIconHelper.GetIconForStatus(status);
                         bool hasQipIcon = contact.XtrazIcon != null ||
                                           (contact.Info != null && contact.Info.QipStatus != 0);

                         if (!hasQipIcon)
                         {
                             contact.StatusIcon = baseIcon;
                             if (contact.Info != null)
                                 contact.Info.Status = status;
                             Debug.WriteLine("[Location] " + uin +
                                             " applying base status fallback: 0x" +
                                             status.ToString("X8"));
                         }
                         else
                         {
                             Debug.WriteLine("[Location] " + uin +
                                             " keeping existing QIP icon, base status=0x" +
                                             status.ToString("X8"));
                         }
                     }

                     if (ContactStatusChanged != null) ContactStatusChanged();
                 }).AsTask();
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[HandleUserInfoReply ERROR] " + ex.Message);
            }
        }

        private void ParseIcbmParams(byte[] data)
        {
            try
            {
                int offset = 0;
                if (data.Length < 16)
                {
                    Debug.WriteLine("[ICBM Params] Too short: " + data.Length +
                                   " hex=" + BitConverter.ToString(data));
                    return;
                }
                ushort channel = ReadU16(data, ref offset);
                uint flags = ReadU32(data, ref offset);
                ushort maxSize = ReadU16(data, ref offset);
                ushort maxSWarn = ReadU16(data, ref offset);
                ushort maxRWarn = ReadU16(data, ref offset);
                uint minIntvl = ReadU32(data, ref offset);

                Debug.WriteLine("[ICBM Params] channel=" + channel +
                                " flags=0x" + flags.ToString("X8") +
                                " maxSize=" + maxSize +
                                " minInterval=" + minIntvl);

                // ВАЖНО: обновляем _icbmMaxSize только для канала 1 (обычный текст).
                // Раньше строка ниже срабатывала для ЛЮБОГО канала — например,
                // отчёт по каналу 2 (rendezvous/файлы) с крошечным maxSize=512
                // затирал нормальный лимит канала 1, из-за чего все сообщения
                // резались до нескольких сотен байт и всё равно не проходили.
                if (channel == 1)
                    _icbmMaxSize = maxSize;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[ICBM Params ERROR] " + ex.Message);
            }
        }
        private void HandleMissedMessage(byte[] data)
        {
            try
            {
                int offset = 0;
                if (data.Length < 2) return;
                ushort channel = ReadU16(data, ref offset);

                byte uinLen = data[offset++];
                string uin = Encoding.UTF8.GetString(data, offset, uinLen);
                offset += uinLen;
                offset += 2; // warning

                ushort tlvCount = ReadU16(data, ref offset);
                for (int i = 0; i < tlvCount && offset + 4 <= data.Length; i++)
                {
                    int po = offset + 2;
                    ushort tl = ReadU16(data, ref po);
                    offset += 4 + tl;
                }

                if (offset + 4 > data.Length) return;
                ushort count = ReadU16(data, ref offset);
                ushort reason = ReadU16(data, ref offset);

                string[] reasons = { "Invalid", "Too large", "Rate exceeded",
                              "Sender too evil", "You too evil" };
                string reasonStr = reason < reasons.Length ? reasons[reason] : "Unknown(" + reason + ")";

                Debug.WriteLine("[MissedMsg] from=" + uin + " channel=" + channel +
                                " count=" + count + " reason=" + reasonStr);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[MissedMsg ERROR] " + ex.Message);
            }
        }

        private async Task HandleUserOfflineAsync(byte[] data)
        {
            try
            {
                int offset = 0;
                while (offset < data.Length)
                {
                    if (offset + 1 > data.Length) break;
                    byte uinLen = data[offset++];
                    if (uinLen == 0 || offset + uinLen > data.Length) break;

                    string uin = Encoding.UTF8.GetString(data, offset, uinLen);
                    offset += uinLen;

                    // пропускаем warning level + tlv count + TLVs
                    if (offset + 2 > data.Length) break;
                    offset += 2; // warning level

                    if (offset + 2 > data.Length) break;
                    ushort tlvCount = ReadU16(data, ref offset);
                    for (int i = 0; i < tlvCount && offset + 4 <= data.Length; i++)
                    {
                        ushort tlvLen = ReadU16(data, ref new int[] { offset + 2 }[0]);
                        offset += 4 + tlvLen;
                    }

                    Debug.WriteLine($"[HandleUserOffline] {uin} went offline");

                    // Снимаем пометку "уже запрашивали capabilities" — при
                    // следующем входе контакта снова отправим SNAC(02,05)
                    // type=0x0004, чтобы узнать актуальный QIP-режим.
                    lock (_capabilitiesRequested)
                    {
                        _capabilitiesRequested.Remove(uin);
                    }

                    await _dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                    {
                        if (contacts == null) return;
                        var contact = contacts.FirstOrDefault(c => c.Uin == uin);
                        if (contact != null)
                        {
                            contact.StatusIcon = "/Assets/statuses/offline.png";
                            if (ContactStatusChanged != null) ContactStatusChanged();
                            contact.IsNewOnline = false;
                        }
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HandleUserOffline ERROR] {ex}");
            }
        }

        private async Task HandleServiceFamilies(ushort[] families)
        {
            try
            {
                Debug.WriteLine("[HandleServiceFamilies] Processing server-supported families...");
                Debug.WriteLine($"[HandleServiceFamilies] Server supports: {string.Join(", ", families.Select(f => $"0x{f:X4}"))}");

                // Filter to only families we support
                var supportedFamilies = families.Where(f => IcqSupportedFamilies.Contains(f)).ToArray();

                if (supportedFamilies.Length == 0)
                {
                    Debug.WriteLine("[HandleServiceFamilies] No common families with server!");
                    return;
                }

                Debug.WriteLine($"[HandleServiceFamilies] Requesting versions for: {string.Join(", ", supportedFamilies.Select(f => $"0x{f:X4}"))}");

                // Request service versions for supported families
                await SendServiceVersionsRequestAsync(supportedFamilies);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HandleServiceFamilies ERROR] {ex.Message}");
            }
        }

        // ── Вспомогательный: построить META запрос ──────────────────────────
        private byte[] BuildMetaRequest(ushort subtype, ushort seq, byte[] body)
        {
            uint ownerUin = uint.Parse(_uin);

            using (var inner = new MemoryStream())
            {
                // Всё в little-endian внутри META
                ushort bodyLen = (ushort)(body != null ? body.Length : 0);
                ushort chunkSize = (ushort)(2 + 4 + 2 + 2 + bodyLen); // size field не считает себя

                WriteU16LE(inner, chunkSize);       // data chunk size (LE)
                WriteU32LE(inner, ownerUin);        // owner uin (LE)
                WriteU16LE(inner, 0x07D0);          // META_DATA_REQ (LE)
                WriteU16LE(inner, seq);             // sequence (LE)
                WriteU16LE(inner, subtype);         // subtype (LE)
                if (body != null)
                    inner.Write(body, 0, body.Length);

                byte[] innerData = inner.ToArray();

                // Оборачиваем в TLV(0x0001)
                using (var outer = new MemoryStream())
                {
                    WriteU16BE(outer, 0x0001);              // TLV type
                    WriteU16BE(outer, (ushort)innerData.Length);
                    outer.Write(innerData, 0, innerData.Length);
                    return outer.ToArray();
                }
            }
        }

        private void WriteU16LE(MemoryStream ms, ushort v)
        {
            ms.WriteByte((byte)(v & 0xFF));
            ms.WriteByte((byte)(v >> 8));
        }

        private void WriteU32LE(MemoryStream ms, uint v)
        {
            ms.WriteByte((byte)(v & 0xFF));
            ms.WriteByte((byte)((v >> 8) & 0xFF));
            ms.WriteByte((byte)((v >> 16) & 0xFF));
            ms.WriteByte((byte)((v >> 24) & 0xFF));
        }

        // ── Asciiz строка с LE length-prefix ────────────────────────────────
        private void WriteAsciiz(MemoryStream ms, string s)
        {
            byte[] b = Encoding.UTF8.GetBytes(s ?? "");
            WriteU16LE(ms, (ushort)(b.Length + 1)); // +1 для нулевого байта
            ms.Write(b, 0, b.Length);
            ms.WriteByte(0x00); // null terminator
        }

        // ── Поиск по UIN — subtype 0x051F ───────────────────────────────────
        public async Task<List<SearchResult>> SearchByUinAsync(string uin, ushort seq)
        {
            uint uinNum = uint.Parse(uin);

            using (var body = new MemoryStream())
            {
                // TLV(0x0136) — UIN в виде dword LE
                body.WriteByte(0x36); body.WriteByte(0x01); // type=0x0136 LE
                body.WriteByte(0x04); body.WriteByte(0x00); // len=4 LE
                WriteU32LE(body, uinNum);

                byte[] payload = BuildMetaRequest(0x0569, seq, body.ToArray());
                await SendSnacAsync(0x15, 0x02, 0x0001, GetNextRequestID(), payload);
                Debug.WriteLine("[Search] Sent SearchByUin(TLV) " + uin);
            }

            return await WaitForSearchResults();
        }

        // ── Запрос полной анкеты другого пользователя ───────────────────────
        // Последовательность из документации: "Retrieving full user
        // information (for another user)" — SNAC(15,02)/07D0/04D0 запрос,
        // сервер отвечает несколькими SNAC(15,03)/07DA/xxxx. Здесь разбирается
        // базовая секция (00C8) — имя, фамилия, ник, email и контакты.
        public Task<UserFullInfo> RequestFullUserInfoDetailedAsync(string uin, ushort seq)
        {
            var tcs = new TaskCompletionSource<UserFullInfo>();

            Action<UserFullInfo> handler = null;
            handler = (info) =>
            {
                UserInfoReceived -= handler;
                tcs.TrySetResult(info);
            };
            UserInfoReceived += handler;

            Task.Run(async () =>
            {
                uint uinNum;
                if (!uint.TryParse(uin, out uinNum))
                {
                    UserInfoReceived -= handler;
                    tcs.TrySetResult(null);
                    return;
                }

                using (var body = new MemoryStream())
                {
                    WriteU32LE(body, uinNum);
                    byte[] payload = BuildMetaRequest(0x04D0, seq, body.ToArray());
                    await SendSnacAsync(0x15, 0x02, 0x0001, GetNextRequestID(), payload);
                    Debug.WriteLine("[FullUserInfo] Sent request for uin=" + uin);
                }
            });

            Task.Delay(8000).ContinueWith(_ =>
            {
                UserInfoReceived -= handler;
                tcs.TrySetResult(null);
            });

            return tcs.Task;
        }

        public class UserFullInfo
        {
            public string Nickname { get; set; }
            public string FirstName { get; set; }
            public string LastName { get; set; }
            public string Email { get; set; }
            public string HomeCity { get; set; }
            public string HomeState { get; set; }
            public string HomePhone { get; set; }
            public string HomeFax { get; set; }
            public string HomeAddress { get; set; }
            public string CellPhone { get; set; }
            public string HomeZip { get; set; }
            public ushort HomeCountryCode { get; set; }
            public byte GmtOffset { get; set; }
            public byte AuthFlag { get; set; }
            public byte WebAware { get; set; }
            public byte DirectConnectPerm { get; set; }
            public byte PublishEmail { get; set; }
        }


        // ── Поиск по деталям — subtype 0x0515 ───────────────────────────────
        public async Task<List<SearchResult>> SearchByDetailsAsync(
            string firstName, string lastName, string nick, ushort seq)
        {
            using (var body = new MemoryStream())
            {
                // Порядок из дампа: nick, first, last — все ASCIIZ с LE len-prefix
                WriteAsciiz(body, nick);
                WriteAsciiz(body, firstName);
                WriteAsciiz(body, lastName);

                byte[] payload = BuildMetaRequest(0x0533, seq, body.ToArray());
                await SendSnacAsync(0x15, 0x02, 0x0001, GetNextRequestID(), payload);
                Debug.WriteLine("[Search] Sent SearchByDetails(whitepages)");
            }

            return await WaitForSearchResults();
        }

        // ── Поиск по email — subtype 0x0529 ─────────────────────────────────
        public async Task<List<SearchResult>> SearchByEmailAsync(string email, ushort seq)
        {
            using (var body = new MemoryStream())
            {
                // TLV(0x015E) — email string
                body.WriteByte(0x5E); body.WriteByte(0x01); // type=0x015E LE
                byte[] emailBytes = Encoding.UTF8.GetBytes(email);
                ushort emailTlvLen = (ushort)(emailBytes.Length + 1); // +null
                body.WriteByte((byte)(emailTlvLen & 0xFF));
                body.WriteByte((byte)(emailTlvLen >> 8));
                body.Write(emailBytes, 0, emailBytes.Length);
                body.WriteByte(0x00); // null terminator

                // TLV(0x0230) — flags (из дампа: 02 01 00 00)
                body.WriteByte(0x30); body.WriteByte(0x02);
                body.WriteByte(0x04); body.WriteByte(0x00);
                body.WriteByte(0x01); body.WriteByte(0x00); body.WriteByte(0x00); body.WriteByte(0x00);

                byte[] payload = BuildMetaRequest(0x0573, seq, body.ToArray());
                await SendSnacAsync(0x15, 0x02, 0x0001, GetNextRequestID(), payload);
                Debug.WriteLine("[Search] Sent SearchByEmail(TLV) " + email);
            }

            return await WaitForSearchResults();
        }

        // ── Приём результатов поиска ─────────────────────────────────────────
        private async Task<List<SearchResult>> ReceiveSearchResults(
            ushort seq, TimeSpan timeout)
        {
            var results = new List<SearchResult>();
            var deadline = DateTime.UtcNow + timeout;

            while (DateTime.UtcNow < deadline)
            {
                var flap = await ReceiveFlapWithTimeout(deadline - DateTime.UtcNow);
                if (flap == null) break;
                if (flap.Channel != 0x02 || flap.Data.Length < 10) continue;

                var snac = SnacPacket.Parse(flap.Data);
                if (snac == null) continue;

                // Ищем SNAC(15,03)
                if (snac.Family != 0x0015 || snac.Subtype != 0x0003)
                {
                    // Другие пакеты — обрабатываем нормально и продолжаем ждать
                    await HandleFlapAsync(flap);
                    continue;
                }

                // Парсим META ответ
                bool isLast = false;
                ParseSearchResponse(snac.Data, results, out isLast);

                if (isLast) break;
            }

            Debug.WriteLine("[Search] Got " + results.Count + " results");
            return results;
        }

        private Task<List<SearchResult>> WaitForSearchResults()
        {
            var tcs = new TaskCompletionSource<List<SearchResult>>();
            var allResults = new List<SearchResult>();

            Action<List<SearchResult>, bool> handler = null;
            handler = (results, isLast) =>
            {
                allResults.AddRange(results);
                if (isLast)
                {
                    SearchResultReceived -= handler;
                    tcs.TrySetResult(allResults);
                }
            };
            SearchResultReceived += handler;

            // Таймаут 10 секунд
            Task.Delay(10000).ContinueWith(_ =>
            {
                SearchResultReceived -= handler;
                tcs.TrySetResult(allResults);
            });

            return tcs.Task;
        }

        // ── Парсинг SNAC(15,03) ответа ──────────────────────────────────────
        private void ParseSearchResponse(byte[] data, List<SearchResult> results, out bool isLast)
        {
            isLast = false;
            Debug.WriteLine("[ParseSearch] Data length=" + data.Length +
                            " hex=" + BitConverter.ToString(data));
            try
            {
                int offset = 0;
                while (offset + 4 <= data.Length)
                {
                    ushort tlvType = ReadU16(data, ref offset);
                    ushort tlvLen = ReadU16(data, ref offset);
                    Debug.WriteLine("[ParseSearch] TLV type=0x" + tlvType.ToString("X4") +
                                    " len=" + tlvLen);
                    if (offset + tlvLen > data.Length) break;

                    if (tlvType == 0x0001)
                    {
                        Debug.WriteLine("[ParseSearch] Found TLV(0001), parsing META reply...");
                        ParseMetaSearchReply(data, offset, tlvLen, results, out isLast);
                    }
                    offset += tlvLen;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[ParseSearch ERROR] " + ex);
            }
        }

        private void ParseMetaSearchReply(byte[] data, int start, int len,
            List<SearchResult> results, out bool isLast)
        {
            isLast = false;
            int offset = start;
            int end = start + len;

            if (offset + 10 > end) return;

            // LE header: chunkSize(2) ownerUin(4) dataType(2) seq(2)
            offset += 2; // chunk size
            offset += 4; // owner uin
            offset += 2; // data type (должен быть 0x07DA)
            offset += 2; // sequence

            if (offset + 2 > end) return;
            ushort subtype = ReadU16LE(data, ref offset);

            Debug.WriteLine("[Search] META reply subtype=0x" + subtype.ToString("X4"));

            // 0x01AE — последний результат (или единственный для UIN поиска)
            // 0x01A4 — промежуточный результат
            if (subtype == 0x01AE)
            {
                isLast = true;
                // Может содержать последний результат
                if (offset + 1 > end) return;
                byte success = data[offset++];
                if (success != 0x0A) return; // не SEARCH_SUCCESS

                var r = ParseSearchRecord(data, ref offset, end);
                if (r != null) results.Add(r);
            }
            else if (subtype == 0x01A4)
            {
                if (offset + 1 > end) return;
                byte success = data[offset++];
                if (success != 0x0A) return;

                var r = ParseSearchRecord(data, ref offset, end);
                if (r != null) results.Add(r);
            }
            else if (subtype == 0x00C8) // META_BASIC_USERINFO — ответ на "полная анкета"
            {
                ParseFullUserInfoBasic(data, offset, end);
            }
        }

        // Базовая анкета пользователя: имя, фамилия, ник, email, город и т.д.
        // Формат по документации SNAC(15,03)/07DA/00C8 (META_BASIC_USERINFO):
        // success byte + 11 ASCIIZ(LE-length) строк + country code(word LE)
        // + GMT offset + auth flag + webaware + dc perms + publish email.
        private void ParseFullUserInfoBasic(byte[] data, int offset, int end)
        {
            try
            {
                if (offset + 1 > end) return;
                byte success = data[offset++];
                if (success != 0x0A)
                {
                    Debug.WriteLine("[FullUserInfo] success byte != 0x0A, анкета недоступна");
                    return;
                }

                var info = new UserFullInfo();
                info.Nickname = ReadAsciizLE(data, ref offset, end);
                info.FirstName = ReadAsciizLE(data, ref offset, end);
                info.LastName = ReadAsciizLE(data, ref offset, end);
                info.Email = ReadAsciizLE(data, ref offset, end);
                info.HomeCity = ReadAsciizLE(data, ref offset, end);
                info.HomeState = ReadAsciizLE(data, ref offset, end);
                info.HomePhone = ReadAsciizLE(data, ref offset, end);
                info.HomeFax = ReadAsciizLE(data, ref offset, end);
                info.HomeAddress = ReadAsciizLE(data, ref offset, end);
                info.CellPhone = ReadAsciizLE(data, ref offset, end);
                info.HomeZip = ReadAsciizLE(data, ref offset, end);

                if (offset + 2 <= end) info.HomeCountryCode = ReadU16LE(data, ref offset);
                if (offset + 1 <= end) info.GmtOffset = data[offset++];
                if (offset + 1 <= end) info.AuthFlag = data[offset++];
                if (offset + 1 <= end) info.WebAware = data[offset++];
                if (offset + 1 <= end) info.DirectConnectPerm = data[offset++];
                if (offset + 1 <= end) info.PublishEmail = data[offset++];

                Debug.WriteLine("[FullUserInfo] " + info.FirstName + " " + info.LastName +
                                " nick=" + info.Nickname + " email=" + info.Email);

                UserInfoReceived?.Invoke(info);

                // Тот же самый пакет нужен и для RequestFullUserInfoAsync/
                // AccountInfoPage — тот путь слушает событие OwnInfoReceived
                // и ждёт UserBasicInfo, но реальный разбор ответа приходит
                // именно сюда (HandleMetaResponseExtended с этим никогда не
                // связан — мёртвый код). Пересобираем те же поля во второй
                // DTO и шлём отдельным событием, чтобы обе стороны получили
                // свои данные из одного и того же пакета.
                var basicInfo = new UserBasicInfo
                {
                    Nick = info.Nickname,
                    FirstName = info.FirstName,
                    LastName = info.LastName,
                    Email = info.Email,
                    City = info.HomeCity,
                    State = info.HomeState,
                    HomePhone = info.HomePhone,
                    HomeFax = info.HomeFax,
                    Address = info.HomeAddress,
                    CellPhone = info.CellPhone,
                    ZipCode = info.HomeZip,
                    Country = info.HomeCountryCode,
                    GmtOffset = info.GmtOffset,
                    AuthFlag = info.AuthFlag,
                    WebAware = info.WebAware
                };
                OwnInfoReceived?.Invoke(basicInfo);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[FullUserInfo ERROR] " + ex.Message);
            }
        }

        private SearchResult ParseSearchRecord(byte[] data, ref int offset, int end)
        {
            try
            {
                if (offset + 2 > end) return null;
                ushort dataSize = ReadU16LE(data, ref offset); // LE!

                if (offset + 4 > end) return null;
                uint uin = ReadU32LE(data, ref offset); // LE!

                string nick = ReadAsciizLE(data, ref offset, end);
                string first = ReadAsciizLE(data, ref offset, end);
                string last = ReadAsciizLE(data, ref offset, end);
                string email = ReadAsciizLE(data, ref offset, end);

                if (offset + 1 > end) return null;
                byte authFlag = data[offset++];

                if (offset + 2 > end) return null;
                ushort onlineStatus = ReadU16LE(data, ref offset);

                if (offset + 1 > end) return null;
                byte gender = data[offset++];

                if (offset + 2 > end) return null;
                ushort age = ReadU16LE(data, ref offset);

                Debug.WriteLine("[Search] Found: uin=" + uin + " nick=" + nick +
                                " name=" + first + " " + last + " online=" + (onlineStatus == 1));

                return new SearchResult
                {
                    Uin = uin.ToString(),
                    Nick = nick,
                    FirstName = first,
                    LastName = last,
                    Email = email,
                    IsOnline = onlineStatus == 1,
                    Gender = gender,
                    Age = age
                };
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[ParseSearchRecord ERROR] " + ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Удаление аккаунта — SNAC(15,02)/07D0/04C4 CLI_UNREGISTER_USER
        /// V2 — без CTS.Register (крашит UWP) + с RunContinuationsAsynchronously
        /// Возвращает true если сервер прислал META_UNREGISTER_ACK с 0x0A
        /// </summary>
        public async Task<bool> DeleteAccountAsync(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password empty", nameof(password));

            uint uinNum;
            if (!uint.TryParse(_uin, out uinNum))
                throw new Exception("Invalid UIN format: " + _uin);

            byte[] passBytes = Encoding.UTF8.GetBytes(password + "\0");
            ushort passLen = (ushort)passBytes.Length;

            byte[] body;
            using (var bodyMs = new MemoryStream())
            {
                WriteU32LE(bodyMs, uinNum);
                WriteU16LE(bodyMs, passLen);
                bodyMs.Write(passBytes, 0, passBytes.Length);
                body = bodyMs.ToArray();
            }

            ushort metaSeq = GetNextRequestID();
            byte[] payload = BuildMetaRequest(0x04C4, metaSeq, body);

            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_deleteLock)
            {
                _deleteAccountTcs = tcs;
                _isDeleting = true;
            }

            try
            {
                Debug.WriteLine("[DeleteAccount V2] Sending 04C4, metaSeq=" + metaSeq);
                await SendSnacAsync(0x15, 0x02, 0x0000, GetNextRequestID(), payload);

                var timeoutTask = Task.Delay(TimeSpan.FromSeconds(15));
                var winner = await Task.WhenAny(tcs.Task, timeoutTask);

                if (winner == timeoutTask)
                    throw new TimeoutException("Сервер не ответил на META_UNREGISTER_ACK (15,03/00B4)");

                bool ok = await tcs.Task;
                Debug.WriteLine("[DeleteAccount V2] Result: " + (ok ? "SUCCESS 0x0A" : "FAIL"));
                return ok;
            }
            finally
            {
                lock (_deleteLock)
                {
                    _deleteAccountTcs = null;
                }
            }
        }

        public Task<bool> DeleteAccountAsync()
        {
            return DeleteAccountAsync(_password);
        }

        private void CompleteDeleteAccount(bool success)
        {
            TaskCompletionSource<bool> tcs = null;
            lock (_deleteLock) { tcs = _deleteAccountTcs; }
            tcs?.TrySetResult(success);
        }

        public async Task DisconnectAfterDeleteAsync()
        {
            try
            {
                _isDeleting = true;
                try { _receiveCts?.Cancel(); } catch { }
                _receiveCts = null;
                await Task.Delay(400);

                try { _writer?.DetachStream(); } catch { }
                try { _writer?.Dispose(); } catch { }
                _writer = null;
                try { _reader?.DetachStream(); } catch { }
                try { _reader?.Dispose(); } catch { }
                _reader = null;
                try { _socket?.Dispose(); } catch { }
                _socket = null;
                try { ControlChannelService.Instance.Cleanup(); } catch { }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[DisconnectAfterDelete ERROR] " + ex.Message);
            }
        }

        // ── LE читалки ───────────────────────────────────────────────────────
        private ushort ReadU16LE(byte[] data, ref int offset)
        {
            ushort v = (ushort)(data[offset] | (data[offset + 1] << 8));
            offset += 2;
            return v;
        }

        private uint ReadU32LE(byte[] data, ref int offset)
        {
            uint v = (uint)(data[offset] |
                            (data[offset + 1] << 8) |
                            (data[offset + 2] << 16) |
                            (data[offset + 3] << 24));
            offset += 4;
            return v;
        }

        private string ReadAsciizLE(byte[] data, ref int offset, int end)
        {
            if (offset + 2 > end) return "";
            ushort len = ReadU16LE(data, ref offset);
            if (len == 0) return "";
            if (offset + len > end) return "";
            // ASCIIZ: убираем нулевой байт в конце
            int textLen = len > 0 && data[offset + len - 1] == 0 ? len - 1 : len;
            string s = DecodeWin1251(data, offset, textLen);
            offset += len;
            return s;
        }

        // ── Добавление контакта (SNAC 13,08) ────────────────────────────────
        public async Task AddContactAsync(string uin, string displayName)
        {
            ushort newItemId = GenerateItemId();

            ushort targetGroupId = 0;
            string targetGroupName = "";

            if (contacts != null)
            {
                var temp = contacts.FirstOrDefault(c => c.Uin == uin && c.IsTemporary);
                if (temp != null)
                    await _dispatcher.RunAsync(CoreDispatcherPriority.Normal,
                        () => contacts.Remove(temp));
            }

            foreach (var g in _ssiGroups.Values)
            {
                if (g.GroupId != 0x0000)
                {
                    targetGroupId = g.GroupId;
                    targetGroupName = g.Name;
                    break;
                }
            }

            if (targetGroupId == 0)
                throw new Exception("Нет доступных групп");

            byte[] nameTlvData = Encoding.UTF8.GetBytes(displayName);
            using (var tlvMs = new MemoryStream())
            {
                WriteU16BE(tlvMs, 0x0131);
                WriteU16BE(tlvMs, (ushort)nameTlvData.Length);
                tlvMs.Write(nameTlvData, 0, nameTlvData.Length);
                WriteU16BE(tlvMs, 0x013A); WriteU16BE(tlvMs, 0x0000);
                WriteU16BE(tlvMs, 0x013C); WriteU16BE(tlvMs, 0x0000);
                WriteU16BE(tlvMs, 0x0137); WriteU16BE(tlvMs, 0x0000);

                byte[] contactTlv = tlvMs.ToArray();

                await SendSnacAsync(0x13, 0x11, 0x00, GetNextRequestID(), null);
                await Task.Delay(100);

                await SendSnacAsync(0x13, 0x08, 0x00, GetNextRequestID(),
                    BuildSsiItem(uin, targetGroupId, newItemId, 0x0000, contactTlv));

                ushort r1 = await WaitForSsiAck();
                Debug.WriteLine("[SSI] Add buddy result: " + GetSsiResultText(r1));
                if (r1 != 0x0000)
                    throw new Exception("SSI ошибка добавления: " + GetSsiResultText(r1));

                await Task.Delay(100);

                var group = _ssiGroups[targetGroupId];
                if (!group.MemberIds.Contains(newItemId))
                    group.MemberIds.Add(newItemId);

                byte[] c8Data = new byte[group.MemberIds.Count * 2];
                for (int i = 0; i < group.MemberIds.Count; i++)
                {
                    c8Data[i * 2] = (byte)(group.MemberIds[i] >> 8);
                    c8Data[i * 2 + 1] = (byte)(group.MemberIds[i] & 0xFF);
                }

                await SendSnacAsync(0x13, 0x09, 0x00, GetNextRequestID(),
                    BuildSsiItem(targetGroupName, targetGroupId, 0x0000,
                                 0x0001, BuildTlv(0x00C8, c8Data)));

                await SendSnacAsync(0x13, 0x12, 0x00, GetNextRequestID(), null);

                ushort r2 = await WaitForSsiAck();
                Debug.WriteLine("[SSI] Update group result: " + GetSsiResultText(r2));
            }

            var newContact = new Contact
            {
                Uin = uin,
                Name = displayName,
                GroupId = targetGroupId,
                ItemId = newItemId,
                Group = targetGroupName,
                StatusIcon = "/Assets/statuses/offline.png"
            };

            if (contacts != null)

                await _dispatcher.RunAsync(CoreDispatcherPriority.Normal,
                    () => contacts.Add(newContact));

            await RequestUserInfoAsync(uin);

            if (ContactStatusChanged != null) ContactStatusChanged();
            Debug.WriteLine("[SSI] Added: " + uin);
        }

        private ushort GenerateItemId()
        {
            // Находим максимальный существующий itemId и берём следующий
            ushort maxId = 0;
            if (contacts != null)
            {
                foreach (var c in contacts)
                    if (c.ItemId > maxId) maxId = c.ItemId;
            }
            return (ushort)(maxId + 1);
        }

        // ── Запрос информации о клиенте контакта (SNAC 02,05) ──────────────
        // type:
        //   0x0001 — general info (UIN, ник, профиль) → ответ 0x02, 0x03
        //   0x0002 — short online info
        //   0x0003 — away message
        //   0x0004 — client capabilities (QIP- и X-статусы!) — ГЛАВНОЕ
        //
        // На kicq (iserverd) QIP-режим контакта НЕ приходит в SNAC(03,0B) и
        // НЕ приходит в SNAC(03,0F) — там только базовый статус. Чтобы
        // узнать, активен ли у контакта QIP-режим прямо сейчас, клиент
        // должен явно запросить capabilities через этот SNAC. Ответ
        // (SNAC 02,06) придёт в HandleUserInfoReply, где в dependent
        // part будет TLV 0x0005 со списком 16-байтных CLSID'ов.
        public async Task RequestUserInfoAsync(string uin, ushort infoType = 0x0001)
        {
            try
            {
                byte[] uinBytes = Encoding.UTF8.GetBytes(uin);
                using (var ms = new MemoryStream())
                {
                    WriteU16BE(ms, infoType);             // type: 1=general, 3=away, 4=caps
                    ms.WriteByte((byte)uinBytes.Length);
                    ms.Write(uinBytes, 0, uinBytes.Length);
                    await SendSnacAsync(0x02, 0x05, 0x0000, GetNextRequestID(), ms.ToArray());
                    Debug.WriteLine("[Location] Requested info type=0x" +
                                    infoType.ToString("X4") + " for " + uin);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[Location] RequestUserInfo error: " + ex.Message);
            }
        }

        private async Task HandleServiceVersionsResponse(byte[] data)
        {
            try
            {
                Debug.WriteLine("[HandleServiceVersionsResponse] Processing service versions...");

                if (data.Length < 10)
                {
                    Debug.WriteLine("[HandleServiceVersionsResponse] Invalid data length");
                    return;
                }

                // Здесь можно добавить обработку полученных версий сервисов
                Debug.WriteLine($"[HandleServiceVersionsResponse] Data: {BitConverter.ToString(data)}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HandleServiceVersionsResponse ERROR] {ex.Message}");
            }
        }

        // Вызывать на СТАРОМ (умирающем) экземпляре ПЕРЕД тем, как
        // ReconnectService создаст новый OscarProtocol для переподключения.
        //
        // ПРИЧИНА: ControlChannelService.Instance — синглтон на весь процесс.
        // Если новый OscarProtocol вызовет InitializeAsync() до того, как
        // старый экземпляр полностью очистил свой _trigger/сокет — новый
        // _trigger молча затирает старый, а старая TCP-сессия может остаться
        // не до конца закрытой на сервере. Именно это давало: (а) несколько
        // подряд "Connection closed during data read" пока всё не устаканится,
        // и (б) "New client with same UIN connected" — сервер видел одновременно
        // старую недобитую сессию и новую, кикал одну из них по кругу.
        //
        // Безопасно вызывать даже если соединение уже мертво (SendFlapAsync
        // внутри тихо падает и игнорируется, как и раньше в DisconnectAsync).
        public async Task TeardownForReconnectAsync()
        {
            try
            {
                Debug.WriteLine("[OscarProtocol] TeardownForReconnect: начало");
                await DisconnectAsync();

                // Даём серверу и ОС время реально обработать закрытие сокета
                // (FIN/RST), прежде чем новый экземпляр откроет новое
                // соединение с тем же UIN — иначе сервер иногда ещё видит
                // старую сессию живой в момент нового логина.
                await Task.Delay(500);

                Debug.WriteLine("[OscarProtocol] TeardownForReconnect: завершено");
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[OscarProtocol] TeardownForReconnect error: " + ex.Message);
            }
        }

        public async Task DisconnectAsync()
        {
            try
            {
                Debug.WriteLine("[OscarProtocol] Disconnecting...");

                // Отменяем receive loop и keep alive первым делом
                if (_receiveCts != null)
                {
                    _receiveCts.Cancel();
                    _receiveCts = null;
                }

                // Ждём немного чтобы receive loop успел выйти
                await Task.Delay(300);

                // Отправляем disconnect FLAP
                try
                {
                    if (_writer != null)
                    {
                        await SendFlapAsync(0x04, new byte[0]);
                        await Task.Delay(100);
                    }
                }
                catch { }

                // Закрываем потоки
                try { _writer?.DetachStream(); } catch { }
                try { _writer?.Dispose(); } catch { }
                _writer = null;

                try { _reader?.DetachStream(); } catch { }
                try { _reader?.Dispose(); } catch { }
                _reader = null;

                try
                {
                    if (_socket != null)
                    {
                        _socket.Dispose(); // Это безопасно прервет поток чтения
                        _socket = null;
                    }
                }
                catch { }

                ControlChannelService.Instance.Cleanup();

                // Очищаем внутренние кэши состояний — после переподключения
                // начнём с чистого листа.
                lock (_capabilitiesRequested)
                {
                    _capabilitiesRequested.Clear();
                }

                Debug.WriteLine("[OscarProtocol] Disconnected.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[OscarProtocol] Disconnect error: " + ex.Message);
            }
        }

        private void HandleServerInitiatedDisconnect(byte[] data)
        {
            string reason = "Соединение закрыто сервером";
            ushort code = 0;

            try
            {
                var tlvs = ParseTlvs(data);

                TLV codeTlv;
                if (tlvs.TryGetValue(0x0009, out codeTlv) && codeTlv.Value.Length >= 2)
                    code = (ushort)((codeTlv.Value[0] << 8) | codeTlv.Value[1]);

                TLV textTlv;
                if (tlvs.TryGetValue(0x000B, out textTlv))
                    reason = Encoding.UTF8.GetString(textTlv.Value, 0, textTlv.Value.Length);
                SoundService.PlayError();
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[Disconnect] Не удалось разобрать причину: " + ex.Message);
            }

            Debug.WriteLine("[Disconnect] code=0x" + code.ToString("X4") + " reason=" + reason);
            DisconnectedByServer?.Invoke(reason);
        }

        private async Task HandleUserOnlineAsync(byte[] data)
        {
            try
            {
                int offset = 0;
                while (offset < data.Length)
                {
                    if (offset + 1 > data.Length) break;
                    byte uinLen = data[offset++];
                    if (uinLen == 0 || offset + uinLen > data.Length) break;

                    string uin = Encoding.UTF8.GetString(data, offset, uinLen);
                    offset += uinLen;

                    if (offset + 2 > data.Length) break;
                    offset += 2; // warning level

                    if (offset + 2 > data.Length) break;
                    ushort tlvCount = ReadU16(data, ref offset);

                    // Собираем всю информацию из TLV
                    var info = new ContactInfo { Uin = uin };
                    uint status = 0;          // базовый OSCAR-статус из TLV 0x0006
                    uint finalStatus = 0;     // после возможной перезаписи QIP
                    int qipStatusId = 0;      // 0 = нет QIP
                    int xStatusId = 0;        // 0 = нет X-Status
                    string xtrazIcon = null;
                    string xStatusTitle = null;
                    string xStatusDesc = null;
                    string awayMessage = null;

                    for (int i = 0; i < tlvCount && offset + 4 <= data.Length; i++)
                    {
                        ushort tlvType = ReadU16(data, ref offset);
                        ushort tlvLen = ReadU16(data, ref offset);
                        int tlvEnd = offset + tlvLen;

                        if (tlvEnd > data.Length) break;

                        // Сюда возвращаются заполненные поля + флаг "был TLV 0x000D"
                        ParseUserStatusTlvs(
                            data, ref offset, tlvEnd, tlvType, tlvLen,
                            ref status, ref finalStatus, ref qipStatusId, ref xStatusId,
                            ref xtrazIcon, ref xStatusTitle, ref xStatusDesc,
                            ref awayMessage, info);
                    }

                    // ── Главное: ВСЕГДА запрашиваем capabilities через SNAC(02,05) type=0x0004
                    /*
                    bool needRequest;
                    lock (_capabilitiesRequested)
                    {
                        needRequest = !_capabilitiesRequested.Contains(uin);
                        if (needRequest)
                            _capabilitiesRequested.Add(uin);
                    }

                    if (needRequest)
                    {
                        try
                        {
                            await RequestUserInfoAsync(uin, 0x0004);


                                lock (_capabilitiesRequested)
                                {
                                    if (_capabilitiesRequested.Contains(uin))
                                    {
                                        _capabilitiesRequested.Remove(uin);
                                    }
                                }
                            // ──────────────────────────────────────────────────────────
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine("[UserOnline] capabilities request error: " + ex.Message);
                        }
                    }*/

                    // Логируем
                    string qipName = qipStatusId != 0 ? QipStatusCodes.GetName(finalStatus) : null;
                    Debug.WriteLine("[UserOnline] " + uin +
                                    " base=0x" + status.ToString("X4") +
                                    (qipName != null ? " (QIP: " + qipName + ")" : "") +
                                    (xStatusId != 0 ? " X-Status=#" + xStatusId : ""));

                    await _dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                    {
                        if (contacts == null) return;
                        var contact = contacts.FirstOrDefault(c => c.Uin == uin);
                        if (contact == null) return;

                        contact.StatusIcon = StatusIconHelper.GetIconForStatus(finalStatus);

                        if (xtrazIcon != null)
                            contact.XtrazIcon = xtrazIcon;
                        else if (xStatusId == 0)
                            contact.XtrazIcon = null;

                        contact.Info = info;
                        contact.IsNewOnline = true;

                        Task.Delay(5000).ContinueWith(_ =>
                            _dispatcher.RunAsync(CoreDispatcherPriority.Normal, () =>
                                contact.IsNewOnline = false).AsTask());

                        if (contact.StatusIcon.Contains("offline"))
                            SoundService.PlayOnline();
                    });

                    if (ContactStatusChanged != null)
                        ContactStatusChanged();

                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[HandleUserOnline ERROR] " + ex);
            }
        }


        private void ParseUserStatusTlvs(
            byte[] data, ref int offset, int tlvEnd,
            ushort tlvType, ushort tlvLen,
            ref uint status, ref uint finalStatus, ref int qipStatusId, ref int xStatusId,
            ref string xtrazIcon, ref string xStatusTitle, ref string xStatusDesc,
            ref string awayMessage,
            ContactInfo info)
        {
            switch (tlvType)
            {
                case 0x0001: // user class
                    if (tlvLen >= 2)
                        info.UserClass = ReadU16(data, ref offset);
                    else
                        offset = tlvEnd;
                    break;

                case 0x0006: // user status — БАЗОВЫЙ OSCAR-СТАТУС (Jasmine: skip 2, read WORD!)
                    if (tlvLen >= 4)
                    {
                        offset += 2;                          // Jasmine: tlvData.skip(2)
                        ushort rawStatus = ReadU16(data, ref offset); // Jasmine: readWord()
                        status = rawStatus;
                        finalStatus = status;
                        info.Status = status;
                    }
                    else
                    {
                        offset = tlvEnd;
                    }
                    break;

                case 0x000A: // external IP
                    if (tlvLen >= 4)
                        info.ExternalIp = ReadU32(data, ref offset);
                    else
                        offset = tlvEnd;
                    break;

                case 0x000F: // online time (seconds)
                    if (tlvLen >= 4)
                        info.OnlineTime = ReadU32(data, ref offset);
                    else
                        offset = tlvEnd;
                    break;

                case 0x0003: // signon time
                    if (tlvLen >= 4)
                        info.SignonTime = ReadU32(data, ref offset);
                    else
                        offset = tlvEnd;
                    break;

                case 0x0005: // member since
                    if (tlvLen >= 4)
                        info.MemberSince = ReadU32(data, ref offset);
                    else
                        offset = tlvEnd;
                    break;

                case 0x000C: // DC info
                    if (tlvLen >= 9)
                    {
                        info.DcInternalIp = ReadU32(data, ref offset);
                        info.DcPort = (ushort)(ReadU32(data, ref offset) & 0xFFFF);
                        info.DcType = data[offset];
                    }
                    offset = tlvEnd;
                    break;

                case 0x000D:
                    {
                        int coff = offset;
                        int cend = offset + tlvLen;
                        int capCount = tlvLen / 16;
                        var capList = new List<string>(capCount);
                        for (int c = 0; c < capCount && coff + 16 <= cend; c++)
                        {
                            var sb = new StringBuilder(32);
                            for (int b = 0; b < 16; b++)
                                sb.Append(data[coff + b].ToString("X2"));
                            string guidHex = sb.ToString();
                            capList.Add(guidHex);

                            uint? qipCode = QipStatusCodes.FromGuid(guidHex);
                            if (qipCode.HasValue)
                            {
                                finalStatus = qipCode.Value;
                                qipStatusId = (int)qipCode.Value;
                                info.QipStatus = finalStatus;
                                info.Status = finalStatus;
                                Debug.WriteLine("[UserStatusTlv] " + info.Uin +
                                                " QIP-status override: 0x" +
                                                finalStatus.ToString("X8") +
                                                " (" + (QipStatusCodes.GetName(finalStatus) ?? "?") + ")");
                            }

                            int? xid = XStatusCodes.FromGuid(guidHex);
                            if (xid.HasValue)
                            {
                                xStatusId = xid.Value;
                                xtrazIcon = guidHex;
                                var xi = XStatusCodes.GetInfo(xid.Value);
                                if (xi != null)
                                {
                                    xStatusTitle = xi.Title;
                                    xStatusDesc = xi.Description;
                                }
                                info.XStatusId = xStatusId;
                                info.XStatusTitle = xStatusTitle;
                                info.XStatusDescription = xStatusDesc;
                            }

                            coff += 16;
                        }
                        info.Capabilities = capList.ToArray();
                        offset = tlvEnd;
                        break;
                    }

                case 0x0019:
                    offset = tlvEnd; // short capabilities — пропускаем
                    break;

                // ────────────────────────────────────────────────────
                // TLV 0x001D — AWAY MESSAGE / X-Status message
                // ────────────────────────────────────────────────────
                case 0x001D:
                    {
                        int moff = offset;
                        int mend = offset + tlvLen;
                        while (moff + 4 <= mend)
                        {
                            ushort subType = ReadU16(data, ref moff);
                            ushort subLen = ReadU16(data, ref moff);
                            if (moff + subLen > mend) break;

                            if (subType == 0x0002 && subLen >= 2)
                            {
                                ushort textLen = (ushort)((data[moff] << 8) | data[moff + 1]);
                                int start = moff + 2;
                                if (textLen > 0 && start + textLen <= mend)
                                {
                                    awayMessage = Encoding.UTF8.GetString(
                                        data, start, textLen);
                                    info.StatusMessage = awayMessage;
                                }
                            }
                            else if (subType == 0x000E && subLen > 0)
                            {
                                string moodStr = Encoding.UTF8.GetString(
                                    data, moff, subLen).ToLower().Trim('\0');
                                info.Mood = moodStr;
                            }

                            moff += subLen;
                        }
                        offset = tlvEnd;
                        break;
                    }

                default:
                    offset = tlvEnd; // неизвестный TLV — пропускаем
                    break;
            }
        }

        public async Task RequestLocationInfoAsync(string uin, ushort requestType = 0x0004)
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                // Type of requesting info (0x0004 = client capabilities)
                writer.Write(SwapUInt16(requestType));

                // User UIN string length + UIN string
                byte[] uinBytes = Encoding.UTF8.GetBytes(uin);
                writer.Write((byte)uinBytes.Length);
                writer.Write(uinBytes);

                // Request ID генерируем стандартно
                uint requestId = GetNextRequestID();

                await SendSnacAsync(0x02, 0x05, 0x0000, requestId, ms.ToArray());
                Debug.WriteLine($"[LocationInfo] Sent SNAC(02,05) Type={requestType} for UIN={uin}");
            }
        }

        private uint ReadU32(byte[] data, ref int offset)
        {
            uint val = (uint)((data[offset] << 24) | (data[offset + 1] << 16) |
                               (data[offset + 2] << 8) | data[offset + 3]);
            offset += 4;
            return val;
        }

        public static class StatusIconHelper
        {
            public static string GetIconForStatus(uint status)
            {
                // Базовый статус — нижние 2 байта
                ushort baseStatus = (ushort)(status & 0xFFFF);

                switch (baseStatus)
                {
                    case 0x0000: return "/Assets/statuses/online.png";
                    case 0x0001: return "/Assets/statuses/away.png";
                    case 0x0002: return "/Assets/statuses/dnd.png";
                    case 0x0004: return "/Assets/statuses/na.png";
                    case 0x0010: return "/Assets/statuses/busy.png";   // occupied
                    case 0x0020: return "/Assets/statuses/f4c.png";    // free4chat
                    case 0x0100: return "/Assets/statuses/inv.png";    // invisible

                    case 0x3000: return "/Assets/statuses/evil.png";  // злой
                    case 0x4000: return "/Assets/statuses/depressed.png"; // депрессия
                    case 0x5000: return "/Assets/statuses/home.png";   // дома
                    case 0x6000: return "/Assets/statuses/work.png";   // работа
                    case 0x2001: return "/Assets/statuses/eating.png"; // обед (0x1001 флаг + 0x2000?)

                    default:
                        Debug.WriteLine("[Status] Unknown status=0x" + status.ToString("X8") +
                                        " base=0x" + baseStatus.ToString("X4"));
                        return "/Assets/statuses/online.png";
                }
            }
        }


        public static class SnacFlags
        {
            public const ushort MoreData = 0x0001;     // More data fragments coming
            public const ushort ServerBusy = 0x0002;   // Server is busy
            public const ushort Error = 0x8000;        // Error response

            public static bool HasMoreData(ushort flags) => (flags & MoreData) != 0;
            public static bool IsServerBusy(ushort flags) => (flags & ServerBusy) != 0;
            public static bool IsError(ushort flags) => (flags & Error) != 0;
        }


        private byte[] SwapUInt32(uint value)
        {
            return new byte[]
            {
        (byte)((value >> 24) & 0xFF),
        (byte)((value >> 16) & 0xFF),
        (byte)((value >> 8) & 0xFF),
        (byte)(value & 0xFF)
            };
        }



        public void Dispose()
        {
            _reader?.Dispose();
            _writer?.Dispose();
            _socket?.Dispose();
        }

        public async Task ReceiveServerSnacsAsync()
        {
            Debug.WriteLine("[SnacReceiver] Starting...");
            _receiveCts = new CancellationTokenSource();
            Task.Run(() => KeepAliveLoopAsync(_receiveCts.Token));

            try
            {
                while (!_receiveCts.IsCancellationRequested)
                {
                    var flap = await ReceiveFlapAsync();
                    if (flap == null) continue;
                    if (flap.Channel == 0x05) continue;

                    if (flap.Channel == 0x04)
                    {
                        HandleServerInitiatedDisconnect(flap.Data);
                        return; // сервер сам закроет сокет следующим пакетом — читать больше нечего
                    }

                    await HandleFlapAsync(flap);
                }
            }
            catch (OperationCanceledException)
            {
                // Намеренное отключение — не ошибка
                Debug.WriteLine("[SnacReceiver] Cancelled.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[SnacReceiver] Connection lost: " + ex.Message);
                _receiveCts?.Cancel();
                throw; // пробрасываем только реальные ошибки для ReconnectService
            }
        }

        private async Task KeepAliveLoopAsync(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    // 30 секунд вместо 60 — быстрее обнаруживаем обрыв
                    await Task.Delay(30000, token);
                    if (token.IsCancellationRequested) break;

                    try
                    {
                        // Таймаут 10 секунд на отправку keep-alive
                        var sendTask = SendFlapAsync(0x05, new byte[0]);
                        var timeout = Task.Delay(10000, token);
                        var completed = await Task.WhenAny(sendTask, timeout);

                        if (completed == timeout)
                        {
                            Debug.WriteLine("[KeepAlive] Timeout — connection dead");
                            OnConnectionLost("KeepAlive timeout");
                            break;
                        }

                        await sendTask; // проверяем исключение
                        Debug.WriteLine("[KeepAlive] Sent");
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex)
                    {
                        Debug.WriteLine("[KeepAlive] Failed: " + ex.Message);
                        // SendFlapAsync уже вызвал OnConnectionLost
                        break;
                    }
                }
            }
            catch (OperationCanceledException) { }
        }

        private byte[] GetPseudoAsciiBytes(string input)
        {
            byte[] result = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                char c = input[i];
                result[i] = (byte)(c <= 0x7F ? c : '?');
            }
            return result;
        }


        public class SnacPacket
        {
            public ushort Family { get; set; }
            public ushort Subtype { get; set; }
            public ushort Flags { get; set; }
            public uint RequestId { get; set; }
            public byte[] Data { get; set; }

            public static SnacPacket Parse(byte[] data)
            {
                if (data == null || data.Length < 10)
                    return null;

                using (var ms = new MemoryStream(data))
                using (var reader = new BinaryReader(ms))
                {
                    return new SnacPacket
                    {
                        Family = (ushort)((reader.ReadByte() << 8) | reader.ReadByte()),
                        Subtype = (ushort)((reader.ReadByte() << 8) | reader.ReadByte()),
                        Flags = (ushort)((reader.ReadByte() << 8) | reader.ReadByte()),
                        RequestId = (uint)((reader.ReadByte() << 24) | (reader.ReadByte() << 16) |
                                           (reader.ReadByte() << 8) | reader.ReadByte()),
                        Data = reader.ReadBytes(data.Length - 10)
                    };
                }
            }

        }

        private string GetSsiResultText(ushort result)
        {
            switch (result)
            {
                case 0x0000: return "Success";
                case 0x0001: return "Database error";
                case 0x0002: return "Not found";
                case 0x0003: return "Already exists";
                case 0x0004: return "Unavailable";
                case 0x000A: return "Bad request";
                case 0x000B: return "Database timeout";
                case 0x000C: return "Max contacts reached";
                case 0x000E: return "Authorization required";
                case 0x0010: return "Bad login ID";
                case 0x0011: return "Too many contacts";
                case 0x001A: return "Timeout";
                default: return "Unknown (0x" + result.ToString("X4") + ")";
            }
        }



        public class FlapFrame
        {
            public byte StartMarker { get; set; }  // Should always be 0x2A
            public byte Channel { get; set; }      // FLAP channel (0x01-0x05)
            public ushort Sequence { get; set; }   // Sequence number
            public ushort DataLength { get; set; } // Length of data
            public byte[] Data { get; set; }       // Actual payload

            public static FlapFrame Parse(byte[] data)
            {
                if (data == null || data.Length < 6)
                    return null;

                using (var ms = new MemoryStream(data))
                using (var reader = new BinaryReader(ms))
                {
                    return new FlapFrame
                    {
                        StartMarker = reader.ReadByte(),
                        Channel = reader.ReadByte(),
                        Sequence = (ushort)((reader.ReadByte() << 8) | reader.ReadByte()),
                        DataLength = (ushort)((reader.ReadByte() << 8) | reader.ReadByte()),
                        Data = reader.ReadBytes(data.Length - 6)
                    };
                }
            }
        }

        // Статусы (нижние 2 байта TLV 0x06)
        public static class UserStatus
        {
            public const ushort Online = 0x0000;
            public const ushort Away = 0x0001;
            public const ushort Dnd = 0x0002;
            public const ushort Na = 0x0004;
            public const ushort Occupied = 0x0010;
            public const ushort Free4Chat = 0x0020;
            public const ushort Invisible = 0x0100;
            public const ushort Evil = 0x3000;
            public const ushort Depressed = 0x4000;
            public const ushort AtHome = 0x5000;
            public const ushort AtWork = 0x6000;
            public const ushort Lunch = 0x2001;
            public const ushort Offline = 0xFFFF;
        }

        // Флаги пользователя (верхние 2 байта TLV 0x06)
        public static class UserFlags
        {
            public const ushort WebAware = 0x0001;
            public const ushort ShowIp = 0x0002;
            public const ushort Birthday = 0x0008;
            public const ushort WebFront = 0x0020;
            public const ushort DcDisabled = 0x0100;
            public const ushort HomePage = 0x0200;
            public const ushort DcAuth = 0x1000;
            public const ushort DcCont = 0x2000;
        }

        public class TLV
        {
            public ushort Type { get; }
            public byte[] Value { get; }

            public TLV(ushort type, byte[] value)
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                Type = type;
                Value = value;
            }
        }
    }
}
