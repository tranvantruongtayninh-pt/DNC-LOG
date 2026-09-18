// netlify/functions/verify-otp.js
//
// Kiểm tra mã 8 số người dùng nhập, so với bản băm đã lưu ở request-otp.js.
// Nếu đúng: xóa mã đã dùng, gắn custom claim "otpVerified" vào tài khoản Firebase Auth.
// Firestore Security Rules sẽ chỉ mở dữ liệu cho tài khoản có claim này — nghĩa là
// việc khóa dữ liệu nằm ở PHÍA MÁY CHỦ (Firestore Rules kiểm tra token), không phải
// ở giao diện, nên không thể bị bỏ qua bằng cách sửa JavaScript trong trình duyệt.

const admin = require("firebase-admin");
const crypto = require("crypto");

function initAdmin() {
  if (!admin.apps.length) {
    const svc = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(svc) });
  }
  return admin;
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
  const code = payload.code;
  if (!idToken || !code) {
    return json(400, { error: "Thiếu idToken hoặc mã OTP" });
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
    const codeRef = db.collection("otpCodes").doc(uid);
    const snap = await codeRef.get();

    if (!snap.exists) {
      return json(400, {
        error: "Chưa yêu cầu mã hoặc mã đã được dùng. Vui lòng bấm \"Gửi lại mã\".",
      });
    }

    const data = snap.data();
    const now = Date.now();

    if (now > data.expiresAt) {
      await codeRef.delete();
      return json(400, { error: "Mã đã hết hạn. Vui lòng bấm \"Gửi lại mã\"." });
    }

    if ((data.attempts || 0) >= 5) {
      await codeRef.delete();
      return json(429, {
        error: "Nhập sai quá 5 lần. Vui lòng bấm \"Gửi lại mã\" để lấy mã mới.",
      });
    }

    const codeHash = sha256(String(code).trim());
    if (codeHash !== data.codeHash) {
      await codeRef.update({ attempts: admin.firestore.FieldValue.increment(1) });
      const remaining = 5 - ((data.attempts || 0) + 1);
      return json(400, {
        error: `Mã không đúng. Còn ${remaining > 0 ? remaining : 0} lần thử.`,
      });
    }

    // Đúng mã: xóa mã đã dùng, cấp claim otpVerified
    await codeRef.delete();
    await adminApp.auth().setCustomUserClaims(uid, { otpVerified: now });

    return json(200, { ok: true });
  } catch (e) {
    console.error("Lỗi verify-otp:", e);
    return json(500, { error: "Lỗi máy chủ: " + e.message });
  }
};
