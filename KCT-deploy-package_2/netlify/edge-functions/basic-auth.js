// Netlify Edge Function — chặn truy cập bằng HTTP Basic Auth
// Chạy ở server (Deno) TRƯỚC khi HTML được gửi về trình duyệt,
// nên không thể bypass bằng cách xem mã nguồn hay tắt JavaScript.

export default async (request, context) => {
  // === Đổi tài khoản/mật khẩu tại đây ===
  const VALID_USER = "DNC2020";
  const VALID_PASS = "Kct2026#*";
  // =======================================

  const authHeader = request.headers.get("authorization") || "";
  const expected = "Basic " + btoa(`${VALID_USER}:${VALID_PASS}`);

  if (authHeader === expected) {
    // Đúng tài khoản/mật khẩu -> cho tiếp tục tới trang gốc
    return context.next();
  }

  // Chưa đăng nhập hoặc sai -> trình duyệt sẽ tự bật popup đăng nhập
  return new Response("Yêu cầu xác thực để truy cập trang này.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="So Du An Xuat Khau KCT"',
      "Content-Type": "text/plain; charset=utf-8",
    },
  });
};

export const config = {
  path: "/*",
};
