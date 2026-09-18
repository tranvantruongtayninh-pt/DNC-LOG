// netlify/functions/clear-otp.js
//
// Gọi khi người dùng bấm "Đăng xuất" — xóa claim otpVerified khỏi tài khoản,
// để lần đăng nhập kế tiếp (kể cả khi Firebase Auth còn nhớ phiên trên trình duyệt)
// vẫn bắt buộc phải xác thực OTP lại từ đầu.

const admin = require("firebase-admin");

function initAdmin() {
  if (!admin.apps.length) {
    const svc = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(svc) });
  }
  return admin;
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

  try {
    const adminApp = initAdmin();
    const decoded = await adminApp.auth().verifyIdToken(idToken);
    await adminApp.auth().setCustomUserClaims(decoded.uid, { otpVerified: null });
    return json(200, { ok: true });
  } catch (e) {
    // Không chặn đăng xuất phía trình duyệt dù bước này lỗi (ví dụ mất mạng) —
    // chỉ ghi log để biết, người dùng vẫn thoát được khỏi ứng dụng bình thường.
    console.error("Lỗi clear-otp:", e.message);
    return json(200, { ok: true, warning: "Không xóa được claim phía máy chủ, nhưng đã đăng xuất." });
  }
};
