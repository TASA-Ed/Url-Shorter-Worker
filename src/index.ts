import page400 from "./res/400.html";
import page302 from "./res/302.html";

// 类型定义
interface Config {
  access_password: string;
  no_ref: "on" | "off";
  cors: "on" | "off";
}

interface RequestBody {
  url?: string;
  password?: string;
  custom_key?: string;
  short_key?: string;
}

interface CustomKeyCheck {
  available: boolean;
  error?: string;
}

interface SuccessResponse {
  success: true;
  data?: string;
  short_key?: string;
  short_url?: string;
  original_url?: string;
}

interface ErrorResponse {
  success: false;
  error: string;
}

type ApiResponse = SuccessResponse | ErrorResponse;

// KV 命名空间类型
interface Env {
  API_KEY: string;
  NO_REF: "on" | "off";
  CORS: "on" | "off";
  LINKSHORTERS: KVNamespace;
}

// 配置
function getConfig(env: Env): Config {
  return {
    // 访问密码
    access_password: env.API_KEY ?? "",
    // 控制 HTTP referrer header
    no_ref: env.NO_REF ?? "off",
    // 允许跨域请求
    cors: env.CORS ?? "on"
  };
}

// 响应头配置
const getResponseHeaders = (env: Env): HeadersInit => {
  const baseHeaders: HeadersInit = {
    "content-type": "application/json;charset=UTF-8",
  };

  if (getConfig(env).cors === "on")
    return {
      ...baseHeaders,
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

  return baseHeaders;
};

/**
 * 生成随机字符串
 */
async function randomString(len: number = 6): Promise<string> {
  const chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';
  let result = '';
  for (let i = 0; i < len; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

/**
 * 验证 URL 格式
 */
function checkURL(url: string): boolean {
  try {
    const urlObj = new URL(url);
    // 检查协议
    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') return false;

    // 检查主机名存在
    if (!urlObj.hostname) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * 保存 URL 到 KV
 */
async function saveUrl(url: string, env: Env, maxRetries: number = 10): Promise<string> {
  for (let i = 0; i < maxRetries; i++) {
    const randomKey = await randomString();
    const isExist = await env.LINKSHORTERS.get(randomKey);

    if (isExist === null) {
      await env.LINKSHORTERS.put(randomKey, url);
      return randomKey;
    }
  }
  throw new Error('Failed to generate unique key after maximum retries');
}

/**
 * 检查自定义短链接是否可用
 */
async function isCustomKeyAvailable(customKey: string, env: Env): Promise<CustomKeyCheck> {
  // 禁止使用保留字段作为 key
  const reservedKeys = ["api", "favicon.ico", "robots.txt"];
  if (reservedKeys.includes(customKey))
    return {
      available: false,
      error: 'This custom key is reserved.'
    };

  // 验证自定义 key 格式（只允许字母数字和连字符）
  if (!/^[a-zA-Z0-9-_]{3,20}$/.test(customKey))
    return {
      available: false,
      error: 'Custom key must be 3-20 characters (letters, numbers, hyphens, underscores only)'
    };

  const isExist = await env.LINKSHORTERS.get(customKey);
  if (isExist)
    return {
      available: false,
      error: 'Custom key already exists'
    };

  return {available: true};
}

/**
 * 验证密码
 */
async function validatePassword(password: string | null, env: Env): Promise<boolean> {
  const configPassword = getConfig(env).access_password;
  if (!configPassword || !password) return false;

  const encoder = new TextEncoder();
  const a = encoder.encode(password);
  const b = encoder.encode(configPassword);

  if (a.byteLength !== b.byteLength) return false;

  // 对比两者的 SHA-256 哈希
  const hashA = await crypto.subtle.digest("SHA-256", a);
  const hashB = await crypto.subtle.digest("SHA-256", b);

  // ArrayBuffer 比较
  const viewA = new Uint8Array(hashA);
  const viewB = new Uint8Array(hashB);
  let diff = 0;
  for (let i = 0; i < viewA.length; i++) {
    diff |= viewA[i] ^ viewB[i];
  }
  return diff === 0;
}

/**
 * 从请求中提取密码
 */
function extractPassword(request: Request, body: RequestBody | string | null = null): string | null {
  // 从 Authorization header 中提取
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer '))
    return authHeader.substring(7);

  // 请求体为 null
  if (!body) return null;

  // 从请求体中提取
  if (typeof body !== "string" && body.password) return body.password;

  // 从请求参数中提取
  if (typeof body === "string" && body) return body;

  return null;
}

/**
 * 创建 JSON 响应
 */
function jsonResponse(data: ApiResponse, status: number = 200, env: Env): Response {
  return new Response(JSON.stringify(data), {
    headers: getResponseHeaders(env),
    status,
  });
}

/**
 * 处理 POST 请求 - 创建短链接
 */
async function handlePost(request: Request, url: URL, env: Env): Promise<Response> {
  const urls = url.pathname.split("/");
  switch (urls[1]) {
    case "api":
      let body: RequestBody;
      try {
        body = await request.json();
      } catch {
        return jsonResponse({
          success: false,
          error: "Invalid JSON body."
        }, 400, env);
      }

      // 验证密码
      const password = extractPassword(request, body);
      if (!await validatePassword(password, env))
        return jsonResponse({
          success: false,
          error: "Invalid password."
        }, 403, env);

      switch (urls[2]) {
        case "create":
          // 验证 URL
          if (!body.url || !checkURL(body.url))
            return jsonResponse({
              success: false,
              error: "Invalid URL format."
            }, 400, env);

          let shortKey: string;

          // 处理自定义短链接
          if (body.custom_key) {
            const customCheck = await isCustomKeyAvailable(body.custom_key, env);
            if (!customCheck.available)
              return jsonResponse({
                success: false,
                error: customCheck.error || "Unknown error"
              }, 400, env);

            shortKey = body.custom_key;
            await env.LINKSHORTERS.put(shortKey, body.url);
          } else {
            // 自动生成短链接
            shortKey = await saveUrl(body.url, env);
          }

          const baseUrl = `${url.protocol}//${url.host}`;
          return jsonResponse({
            success: true,
            short_key: shortKey,
            short_url: `${baseUrl}/${shortKey}`,
            original_url: body.url
          }, 200, env);
        case "delete":
          const keyToDelete = body.short_key;
          if (!keyToDelete) return jsonResponse({success: false, error: "Missing short_key."}, 400, env);
          // 检查是否存在
          if (!await env.LINKSHORTERS.get(keyToDelete)) return jsonResponse({
            success: false,
            error: "The short_key does not exist."
          }, 400, env);

          await env.LINKSHORTERS.delete(keyToDelete);
          return jsonResponse({success: true, data: "Deleted successfully."}, 200, env);
        case undefined:
        case "":
        case "status":
        case "stats":
          return jsonResponse({
            success: true,
            data: "Welcome! Administrator. The URL-Shorter-Worker is running."
          }, 200, env)
        default:
          return jsonResponse({
            success: false,
            error: "Not Found."
          }, 404, env);
      }
    default:
      return jsonResponse({
        success: false,
        error: "Method not allowed."
      }, 405, env);
  }
}

/**
 * 处理 GET 请求 - 访问短链接
 */
async function handleGet(request: Request, url: URL, env: Env): Promise<Response> {
  const urls = url.pathname.split("/");

  switch (urls[1]) {
    case undefined:
    case "":
      // 根路径返回 404
      return new Response(page400.replaceAll("{__code}", "404"), {
        headers: {
          "content-type": "text/html;charset=UTF-8",
        },
        status: 404
      });
    case "favicon.ico":
      // favicon
      const icon = await env.LINKSHORTERS.get("_icon");
      if (!icon)
        return new Response(page400.replaceAll("{__code}", "404"), {
          headers: {
            "content-type": "text/html;charset=UTF-8",
          },
          status: 404
        });
      const binary = Uint8Array.from(atob(icon.slice(25)), c => c.charCodeAt(0));
      return new Response(binary, {
        headers: {
          "content-type": "image/x-icon",
        },
        status: 200
      });
    case "api":
      // 验证密码
      const password = extractPassword(request, url.searchParams.get("password"));
      if (!await validatePassword(password, env))
        return new Response(page400.replaceAll("{__code}", "403"), {
          headers: {
            "content-type": "text/html;charset=UTF-8",
          },
          status: 403
        });
      switch (urls[2]) {
        case undefined:
        case "":
        case "status":
        case "stats":
          return new Response(page400.replaceAll("{__code}", "200"), {
            headers: {
              "content-type": "text/html;charset=UTF-8",
            },
            status: 200
          });
        case "delete":
        case "create":
          return new Response(page400.replaceAll("{__code}", "405"), {
            headers: {
              "content-type": "text/html;charset=UTF-8",
            },
            status: 405
          });
        default:
          return new Response(page400.replaceAll("{__code}", "404"), {
            headers: {
              "content-type": "text/html;charset=UTF-8",
            },
            status: 404
          });
      }
    default:
      // 获取目标 URL
      const targetUrl = await env.LINKSHORTERS.get(urls[1]);

      if (!targetUrl)
        return new Response(page400.replaceAll("{__code}", "404"), {
          headers: {
            "content-type": "text/html;charset=UTF-8",
          },
          status: 404
        });

      // 处理查询参数
      const fullUrl = url.search ? targetUrl + url.search : targetUrl;

      // 重定向
      if (getConfig(env).no_ref === "on") {
        return new Response(page302.replaceAll("{url}", fullUrl), {
          headers: {
            "content-type": "text/html;charset=UTF-8",
          },
        });
      } else {
        return Response.redirect(fullUrl, 302);
      }
  }
}

/**
 * 主请求处理器
 */
async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);

  // 处理 OPTIONS 请求（CORS 预检）
  if (request.method === "OPTIONS")
    return new Response(null, {
      headers: getResponseHeaders(env),
      status: 204
    });


  // 处理 POST 请求 - 创建短链接
  if (request.method === "POST")
    return handlePost(request, url, env);


  // 处理 GET 请求 - 访问短链接
  if (request.method === "GET")
    return handleGet(request, url, env);


  // 其他请求方法不支持
  return jsonResponse({
    success: false,
    error: "Method not allowed"
  }, 405, env);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleRequest(request, env);
  },
};
