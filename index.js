import page404 from "404.html";
import page302 from "302.html";

const config = {
  // 访问密码 - 请修改为你自己的密码
  access_password: "21a1202bd96731b0e4035c0c6613697bdd6859c098368f8834f510656830c983",
  // 基础配置
  no_ref: "off", // 控制 HTTP referrer header
  cors: "on", // 允许跨域请求
  unique_link: true, // 相同的长链接生成相同的短链接
}

let response_header = {
  "content-type": "application/json;charset=UTF-8",
}

if (config.cors === "on") {
  response_header = {
    "content-type": "application/json;charset=UTF-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  }
}

/**
 * 生成随机字符串
 */
async function randomString(len = 6) {
  const chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
  let result = ''
  for (let i = 0; i < len; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return result
}

/**
 * SHA-512 哈希
 */
async function sha512(url) {
  const encoder = new TextEncoder()
  const data = encoder.encode(url)
  const hashBuffer = await crypto.subtle.digest('SHA-512', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * 验证 URL 格式
 */
function checkURL(url) {
  try {
    const urlObj = new URL(url)
    return urlObj.protocol === 'http:' || urlObj.protocol === 'https:'
  } catch {
    return false
  }
}

/**
 * 保存 URL 到 KV
 */
async function saveUrl(url) {
  let randomKey = await randomString()
  let isExist = await LINKSHORTERS.get(randomKey)

  if (isExist === null) {
    await LINKSHORTERS.put(randomKey, url)
    return randomKey
  } else {
    // 如果 key 已存在，递归生成新的
    return saveUrl(url)
  }
}

/**
 * 检查 URL 是否已存在
 */
async function isUrlExist(urlSha512) {
  const isExist = await LINKSHORTERS.get(urlSha512)
  return isExist || false
}

/**
 * 检查自定义短链接是否可用
 */
async function isCustomKeyAvailable(customKey) {
  // 验证自定义 key 格式（只允许字母数字和连字符）
  if (!/^[a-zA-Z0-9-_]{3,20}$/.test(customKey)) {
    return { available: false, error: 'Custom key must be 3-20 characters (letters, numbers, hyphens, underscores only)' }
  }

  const isExist = await LINKSHORTERS.get(customKey)
  if (isExist) {
    return { available: false, error: 'Custom key already exists' }
  }

  return { available: true }
}

/**
 * 验证密码
 */
function validatePassword(password) {
  return password === config.access_password
}

/**
 * 从请求中提取密码
 */
function extractPassword(request, body = null) {
  // 从 Authorization header 中提取
  const authHeader = request.headers.get('Authorization')
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7)
  }

  // 从请求体中提取
  if (body && body.password) {
    return body.password
  }

  return null
}

/**
 * 处理请求
 */
async function handleRequest(request) {
  const url = new URL(request.url)

  // 处理 OPTIONS 请求（CORS 预检）
  if (request.method === "OPTIONS") {
    return new Response(null, {
      headers: response_header,
      status: 204
    })
  }

  // 处理 POST 请求 - 创建短链接
  if (request.method === "POST") {
    let body
    try {
      body = await request.json()
    } catch {
      return new Response(JSON.stringify({
        success: false,
        error: "Invalid JSON body"
      }), {
        headers: response_header,
        status: 400
      })
    }

    // 验证密码
    const password = extractPassword(request, body)
    if (!validatePassword(password)) {
      return new Response(JSON.stringify({
        success: false,
        error: "Invalid password"
      }), {
        headers: response_header,
        status: 401
      })
    }

    // 验证 URL
    if (!body.url || !checkURL(body.url)) {
      return new Response(JSON.stringify({
        success: false,
        error: "Invalid URL format"
      }), {
        headers: response_header,
        status: 400
      })
    }

    let shortKey

    // 处理自定义短链接
    if (body.custom_key) {
      const customCheck = await isCustomKeyAvailable(body.custom_key)
      if (!customCheck.available) {
        return new Response(JSON.stringify({
          success: false,
          error: customCheck.error
        }), {
          headers: response_header,
          status: 400
        })
      }

      shortKey = body.custom_key
      await LINKSHORTERS.put(shortKey, body.url)

      // 如果启用了 unique_link，也存储 hash 映射
      if (config.unique_link) {
        const urlHash = await sha512(body.url)
        await LINKSHORTERS.put(urlHash, shortKey)
      }
    } else {
      // 自动生成短链接
      if (config.unique_link) {
        const urlHash = await sha512(body.url)
        const existingKey = await isUrlExist(urlHash)

        if (existingKey) {
          shortKey = existingKey
        } else {
          shortKey = await saveUrl(body.url)
          await LINKSHORTERS.put(urlHash, shortKey)
        }
      } else {
        shortKey = await saveUrl(body.url)
      }
    }

    const baseUrl = `${url.protocol}//${url.host}`
    return new Response(JSON.stringify({
      success: true,
      short_key: shortKey,
      short_url: `${baseUrl}/${shortKey}`,
      original_url: body.url
    }), {
      headers: response_header,
      status: 200
    })
  }

  // 处理 GET 请求 - 访问短链接
  if (request.method === "GET") {
    const path = url.pathname.split("/")[1]

    // 根路径返回信息
    if (!path) {
      return new Response(page404, {
        headers: {
          "content-type": "text/html;charset=UTF-8",
        },
        status: 404
      })
    }

    // 获取目标 URL
    const targetUrl = await LINKSHORTERS.get(path)

    if (!targetUrl) {
      return new Response(page404, {
        headers: {
          "content-type": "text/html;charset=UTF-8",
        },
        status: 404
      })
    }

    // 处理查询参数
    const fullUrl = url.search ? targetUrl + url.search : targetUrl

    // 重定向
    if (config.no_ref === "on") {
      return new Response(page302.replace("{url}", fullUrl), {
        headers: {
          "content-type": "text/html;charset=UTF-8",
        },
      })
    } else {
      return Response.redirect(fullUrl, 302)
    }
  }

  // 其他请求方法不支持
  return new Response(JSON.stringify({
    success: false,
    error: "Method not allowed"
  }), {
    headers: response_header,
    status: 405
  })
}

// 监听 fetch 事件
addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request))
})
