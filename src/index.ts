// 本文件代码基于 [Url-Shorten-Worker](https://github.com/xyTom/Url-Shorten-Worker) 的逻辑重写。
// 原项目版权归 [xyTom](https://github.com/xyTom) 所有。

import page404 from "./res/404.html";
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

// 环境
export interface Env {
  API_KEY: string;
  NO_REF: "on" | "off";
  CORS: "on" | "off";
  LINKSHORTERS: KVNamespace;
  ASSETS: Fetcher;
}

const reservedKeys: { all: string[], getOnly: string[] } = {
  all: ["index.html", "favicon.ico", "robots.txt", "github.svg", "r", "api-auth"],
  getOnly: ["r", "api-auth"]
};

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
  const result: string[] = [];
  const randomValues = new Uint8Array(len);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < len; i++)
    result.push(chars[randomValues[i] % chars.length]);
  return result.join('');
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
    return !(!urlObj.hostname);
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
  if (reservedKeys.all.includes(customKey))
    return {
      available: false,
      error: 'This custom key is reserved.'
    };

  // 验证自定义 key 格式（只允许字母数字和连字符）
  if (!/^[a-zA-Z0-9-_]{2,20}$/.test(customKey))
    return {
      available: false,
      error: 'Custom key must be 2-20 characters (letters, numbers, hyphens, underscores only)'
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

  // 使用较长的长度进行比较，避免长度泄露
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length; // 长度差异也计入

  for (let i = 0; i < maxLen; i++) {
    const aVal = i < a.length ? a[i] : 0;
    const bVal = i < b.length ? b[i] : 0;
    diff |= aVal ^ bVal;
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
 * 处理 POST 请求
 */
async function handlePost(request: Request, url: URL, env: Env): Promise<Response> {
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

  const path = url.pathname.slice(1); // 移除开头的 /

  // 特殊路由
  if (path === 'api-auth')
    return jsonResponse({
      success: true,
      data: "Welcome! Administrator. The URL-Shorter-Worker is running."
    }, 200, env);

  // 创建短链接
  if (!body.url || !checkURL(body.url))
    return jsonResponse({
      success: false,
      error: "Invalid URL format."
    }, 400, env);

  let shortKey: string;

  // 自定义 key
  if (path && !path.includes('/') && path !== "r") {
    const customCheck = await isCustomKeyAvailable(path, env);
    if (!customCheck.available)
      return jsonResponse({
        success: false,
        error: customCheck.error || "Unknown error"
      }, 400, env);

    shortKey = path;
    await env.LINKSHORTERS.put(shortKey, body.url);
  } else {
    // 自动生成
    shortKey = await saveUrl(body.url, env);
  }

  const baseUrl = `${url.protocol}//${url.host}`;
  return jsonResponse({
    success: true,
    short_key: shortKey,
    short_url: `${baseUrl}/${shortKey}`,
    original_url: body.url
  }, 200, env);
}

/**
 * 处理 GET 请求
 */
async function handleGet(request: Request, url: URL, env: Env): Promise<Response> {
  const urls = url.pathname.split("/");

  // 检查保留路径
  if (reservedKeys.getOnly.includes(urls[1]))
    return new Response(page404, {
      headers: { "content-type": "text/html;charset=UTF-8" },
      status: 404
    });
  if (reservedKeys.all.includes(urls[1]))
    return env.ASSETS.fetch(request);

  // 获取目标 URL
  const targetUrl = await env.LINKSHORTERS.get(urls[1]);

  if (!targetUrl)
    return new Response(page404, {
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

/**
 * 处理 DELETE 请求 - 删除短链接
 */
async function handleDelete(request: Request, url: URL, env: Env): Promise<Response> {
  let body: RequestBody;
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  // 验证密码
  const password = extractPassword(request, body);
  if (!await validatePassword(password, env))
    return jsonResponse({
      success: false,
      error: "Invalid password."
    }, 403, env);

  const path = url.pathname.slice(1); // 移除开头的 /

  if (path.includes('/') || reservedKeys.all.includes(path) || !path)
    return jsonResponse({
      success: false,
      error: "You can't delete reserved key."
    }, 400, env);

  // 检查是否存在
  if (!await env.LINKSHORTERS.get(path)) return jsonResponse({
    success: false,
    error: "The short_key does not exist."
  }, 400, env);

  await env.LINKSHORTERS.delete(path);
  return jsonResponse({success: true, data: "Deleted successfully."}, 200, env);
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

  // 处理 POST 请求
  if (request.method === "POST")
    return handlePost(request, url, env);

  // 处理 GET 请求
  if (request.method === "GET")
    return handleGet(request, url, env);

  // 处理 DELETE 请求 - 删除短链接
  if (request.method === "DELETE")
    return handleDelete(request, url, env);


  // 其他请求方法不支持
  return jsonResponse({
    success: false,
    error: "Method not allowed"
  }, 405, env);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
  },
};
