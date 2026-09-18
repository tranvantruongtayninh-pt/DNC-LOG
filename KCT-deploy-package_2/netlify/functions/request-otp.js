// netlify/functions/request-otp.js
//
// Bước 2 của lớp khóa: sau khi người dùng đăng nhập Email/Password (Firebase Auth)
// thành công ở phía trình duyệt, hàm này được gọi để:
//   1) Xác minh idToken đó thật sự hợp lệ (qua Firebase Admin SDK, không thể giả mạo)
//   2) Tra Chat ID Telegram tương ứng với tài khoản này (đã thiết lập sẵn trong Firestore)
//   3) Tạo mã OTP 8 số, lưu bản BĂM (hash) + hạn 5 phút vào Firestore (KHÔNG lưu mã gốc)
//   4) Gửi mã gốc qua Telegram bằng Bot Token (nằm trong biến môi trường, không lộ ra ngoài)
//
// Biến môi trường cần thiết lập trên Netlify (Site settings → Environment variables):
//   FIREBASE_SERVICE_ACCOUNT  = toàn bộ nội dung file JSON service account (dạng 1 dòng)
//   TELEGRAM_BOT_TOKEN        = token của Bot Telegram (lấy từ @BotFather)

const admin = require("firebase-admin");
const crypto = require("crypto");

function initAdmin() {
  if (!admin.apps.length) {
    const svc = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(svc) });
  }
  return admin;
}

function genOtp8() {
  // 8 chữ số, luôn đủ 8 ký tự (không bị mất số 0 ở đầu)
  const n = crypto.randomInt(0, 100000000);
  return String(n).padStart(8, "0");
}

function sha256(text) {
  return crypto.createHash("sha256").update(String(text)).digest("hex");
}

function json(statusCode, obj) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(obj),
  };
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return json(405, { error: "Method Not Allowed" });
  }

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch (e) {
    return json(400, { error: "Dữ liệu gửi lên không hợp lệ" });
  }

  const idToken = payload.idToken;
  if (!idToken) {
    return json(400, { error: "Thiếu idToken" });
  }

  let adminApp, uid;
  try {
    adminApp = initAdmin();
    const decoded = await adminApp.auth().verifyIdToken(idToken);
    uid = decoded.uid;
  } catch (e) {
    console.error("verifyIdToken thất bại:", e.message);
    return json(401, { error: "Phiên đăng nhập không hợp lệ, vui lòng đăng nhập lại." });
  }

  try {
    const db = adminApp.firestore();

    // 1) Tài khoản này có được thiết lập nhận OTP qua Telegram chưa?
    const recSnap = await db.collection("otpRecipients").doc(uid).get();
    if (!recSnap.exists || !recSnap.data().chatId) {
      return json(403, {
        error:
          "Tài khoản này chưa được thiết lập nhận mã OTP. Vui lòng liên hệ quản trị viên để thêm Chat ID Telegram.",
      });
    }
    const chatId = recSnap.data().chatId;

    // 2) Chặn spam: tối thiểu 30 giây giữa 2 lần gửi
    const codeRef = db.collection("otpCodes").doc(uid);
    const now = Date.now();
    const prevSnap = await codeRef.get();
    if (prevSnap.exists) {
      const prev = prevSnap.data();
      if (prev.lastSentAt && now - prev.lastSentAt < 30000) {
        const waitSec = Math.ceil((30000 - (now - prev.lastSentAt)) / 1000);
        return json(429, { error: `Vui lòng đợi ${waitSec} giây trước khi gửi lại mã.` });
      }
    }

    // 3) Tạo mã, lưu bản băm + hạn 5 phút, KHÔNG lưu mã gốc
    const code = genOtp8();
    const codeHash = sha256(code);
    const expiresAt = now + 5 * 60 * 1000;

    await codeRef.set({
      codeHash,
      expiresAt,
      attempts: 0,
      lastSentAt: now,
    });

    // 4) Gửi qua Telegram
    const token = process.env.TELEGRAM_BOT_TOKEN;
    if (!token) {
      console.error("Thiếu biến môi trường TELEGRAM_BOT_TOKEN");
      return json(500, { error: "Máy chủ chưa cấu hình Bot Telegram. Liên hệ quản trị viên." });
    }

    const text =
      "🔐 Mã xác thực đăng nhập hệ thống KCT của bạn là:\n\n" +
      code +
      "\n\nMã có hiệu lực trong 5 phút. Không chia sẻ mã này cho bất kỳ ai, kể cả người tự xưng là quản trị viên.";

    const tgResp = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text }),
    });
    const tgData = await tgResp.json();

    if (!tgData.ok) {
      console.error("Gửi Telegram thất bại:", tgData);
      return json(502, {
        error:
          "Gửi mã qua Telegram thất bại. Kiểm tra lại Chat ID đã thiết lập cho tài khoản này (Firestore → otpRecipients).",
      });
    }

    return json(200, { ok: true });
  } catch (e) {
    console.error("Lỗi request-otp:", e);
    return json(500, { error: "Lỗi máy chủ: " + e.message });
  }
};
