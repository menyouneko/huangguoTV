package com.huangguo.tv

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.regex.Pattern

/**
 * 黄果(huangguoai.com) 抓取层：规则移植自 huangguo-fongmi 站点脚本，
 * 播放地址解析同步自 Yswag/xptv-extensions 的 huangguo.js：
 * 1) JSON API  POST /api/videos/{id}/episodes/{ep}/playback → data.streams.main|hevc
 * 2) 加密边缘通道 POST /api/playback/request（ECDH P-256 + HKDF-SHA256 + AES-256-GCM，
 *    协议 "dx150-edge-v1"），明文 API 关闭后的兜底
 * 3) 旧版页面抓取（videoInitialData / 页面 m3u8）最后兜底
 * 首页/分类/搜索返回卡片网格 HTML；详情页内嵌 videoInitialData JSON 提供选集。
 */
object HuangguoApi {
    const val UA =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

    // 源站域名会轮换（2026-11 起主站 .com DNS 被污染，官方主用 .io）：
    // 直连候选镜像优先，.io 永远排第一；全部失败再走代理/主站
    private const val ENTRY = "https://huangguoai.ai"  // 官方发布页之一
    private const val ENTRY2 = "https://hgai5.com"     // 旧发布页
    private val KNOWN_MIRRORS = listOf(
        "huangguoai.io", "cb74.bg40t53p.cc", "i8gbw.nt17g20k.cc", "lpiep.nt17g20k.cc", "hi9ly.nt17g20k.cc", "a74c.nt17g20k.cc"
    )
    private val domainRe = Pattern.compile("https://([a-z0-9.-]+\\.(?:cc|com|ai|net|tv|io))")
    @Volatile private var siteBase = "https://huangguoai.com"
    @Volatile private var siteChecked = false
    @Volatile private var lastFailMs = 0L

    val SITE: String
        get() {
            ensureSite()
            return siteBase
        }

    private val probeClient = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .build()

    private fun probe(host: String): Boolean = try {
        val req = Request.Builder().url("https://$host/").header("User-Agent", UA).build()
        probeClient.newCall(req).execute().use { r ->
            r.isSuccessful && (r.body?.string()?.contains("hg-drama-card") == true)
        }
    } catch (_: Exception) {
        false
    }

    private fun ensureSite() {
        if (siteChecked) return
        if (System.currentTimeMillis() - lastFailMs < 300_000) return
        synchronized(this) {
            if (siteChecked) return
            if (probe("huangguoai.com")) {
                siteChecked = true
                return
            }
            for (h in KNOWN_MIRRORS) {
                if (probe(h)) {
                    siteBase = "https://$h"; siteChecked = true; return
                }
            }
            for (entry in listOf(ENTRY, ENTRY2)) {
                try {
                    val req = Request.Builder().url(entry).header("User-Agent", UA).build()
                    probeClient.newCall(req).execute().use { r ->
                        val html = r.body?.string() ?: ""
                        val m = domainRe.matcher(html)
                        val seen = HashSet<String>()
                        while (m.find()) {
                            val h = m.group(1)
                            if (h == "huangguoai.com" || h == "hgai5.com" || h == "huangguoai.ai" ||
                                h.contains("drleao") || h.contains("hzjvlo") ||
                                h.contains("googletagmanager") || h.contains("yandex") ||
                                h.endsWith(".me") || h.contains("x.com") || h.contains("youtube") ||
                                h.contains("tiktok")
                            ) continue
                            if (!seen.add(h)) continue
                            if (probe(h)) {
                                siteBase = "https://$h"; siteChecked = true; return
                            }
                        }
                    }
                } catch (_: Exception) {
                }
            }
            lastFailMs = System.currentTimeMillis() // 全部失败：5 分钟后重试，暂用主站
        }
    }

    val categories = listOf(
        Category("ai-duanju", "AI成人短剧"),
        Category("ai-manju", "AI成人漫剧"),
        Category("ai-huanlian", "AI换脸"),
        Category("ai-mogai", "AI魔改"),
        Category("ranks/hot", "排行榜")
    )

    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    private fun getHtml(url: String, referer: String = "$SITE/"): String {
        val req = Request.Builder().url(url)
            .header("User-Agent", UA)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Language", "zh-CN,zh;q=0.9")
            .header("Referer", referer)
            .build()
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) return ""
            return resp.body?.string() ?: ""
        }
    }

    fun fetchImageBytes(url: String): ByteArray? {
        val req = Request.Builder().url(url)
            .header("User-Agent", UA)
            .header("Referer", "$SITE/")
            .build()
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) return null
            return resp.body?.bytes()
        }
    }

    // ---------- 通用解析 ----------

    private fun fix(u: String?): String {
        if (u.isNullOrEmpty()) return ""
        var s = u.replace("&amp;", "&")
        if (s.startsWith("//")) s = "https:$s"
        else if (s.startsWith("/")) s = SITE + s
        return s
    }

    private val scriptTag = Regex("(?is)<script[\\s\\S]*?</script>")
    private val styleTag = Regex("(?is)<style[\\s\\S]*?</style>")
    private val anyTag = Regex("<[^>]*>")
    private val srOnly = Regex("<span[^>]*class=\"[^\"]*sr-only[^\"]*\"[^>]*>[\\s\\S]*?</span>")

    private fun stripTags(s: String?): String = (s ?: "")
        .replace(srOnly, "")
        .replace(scriptTag, "").replace(styleTag, "").replace(anyTag, "")
        .replace("&nbsp;", " ").replace("&amp;", "&")
        .replace("&quot;", "\"").replace("&#39;", "'")
        .trim()

    private val gridOpen = Pattern.compile("<div\\s+class=\"[^\"]*\\bhg-card-grid\\b[^\"]*\"[^>]*>")
    private val cardOpen = Pattern.compile("<div\\s+class=\"[^\"]*\\bhg-drama-card\\b[^\"]*\"[^>]*>")
    private val cardLink = Pattern.compile("href=\"[^\"]*/(?:detail|video)/(\\d+)/[^\"]*\"")
    private val imgDataSrc = Pattern.compile("data-src=\"([^\"]+)\"")
    private val imgSrc = Pattern.compile("src=\"([^\"]+)\"")
    private val cardTitle = Pattern.compile("hg-drama-card__title[^>]*>([\\s\\S]*?)</a>")
    private val anyLinkTitle = Pattern.compile("<a[^>]+href=\"[^\"]*/(?:detail|video)/\\d+/[^\"]*\"[^>]*>([\\s\\S]*?)</a>")
    private val cardEpisode = Pattern.compile("hg-drama-card__episode[^>]*>([\\s\\S]*?)</span>")
    private val cardEpBase = Pattern.compile("data-ep-base=\"([^\"]*)\"")
    private val cardScore = Pattern.compile("hg-drama-card__score[^>]*>([\\s\\S]*?)</span>")
    private val fallbackLink = Pattern.compile("<a\\b[^>]*href=\"([^\"]*/video/(\\d+)/)[^\"]*\"[^>]*>([\\s\\S]*?)</a>")

    private fun slices(html: String, open: Pattern): List<Int> {
        val starts = ArrayList<Int>()
        val m = open.matcher(html)
        while (m.find()) starts.add(m.end())
        return starts
    }

    private fun blocksOf(html: String, from: Int, to: Int, open: Pattern): List<String> {
        val region = html.substring(from, to)
        val starts = ArrayList<Int>()
        val m = open.matcher(region)
        while (m.find()) starts.add(m.end())
        val out = ArrayList<String>()
        for (i in starts.indices) {
            val end = if (i + 1 < starts.size) starts[i + 1] else region.length
            out.add(region.substring(starts[i], end))
        }
        return out
    }

    private fun group(p: Pattern, s: String, idx: Int): String? {
        val m = p.matcher(s)
        return if (m.find()) m.group(idx) else null
    }

    private fun parseCardBlock(block: String): VideoCard? {
        val idM = cardLink.matcher(block)
        if (!idM.find()) return null
        val id = idM.group(1)
        val imgM = (imgDataSrc.matcher(block).takeIf { it.find() } ?: imgSrc.matcher(block).takeIf { it.find() })
        val titleM = cardTitle.matcher(block)
        var title = if (titleM.find()) stripTags(titleM.group(1)) else ""
        if (title.isEmpty()) {
            val t2 = anyLinkTitle.matcher(block)
            if (t2.find()) title = stripTags(t2.group(1))
        }
        if (title.isEmpty()) return null
        val epM = cardEpisode.matcher(block)
        var rem = if (epM.find()) stripTags(epM.group(1)) else ""
        if (rem.isEmpty()) rem = group(cardEpBase, block, 1) ?: ""
        val scM = cardScore.matcher(block)
        val sc = if (scM.find()) stripTags(scM.group(1)) else ""
        val remarks = if (rem.isNotEmpty() && sc.isNotEmpty()) "$rem · $sc" else (rem.ifEmpty { sc })
        return VideoCard(id, title, fix(imgM?.group(1) ?: ""), remarks)
    }

    private fun parseGridCards(html: String, allGrids: Boolean): List<VideoCard> {
        if (html.isEmpty()) return emptyList()
        val list = ArrayList<VideoCard>()
        val seen = HashSet<String>()
        val starts = slices(html, gridOpen)
        val regions = if (starts.isEmpty()) listOf(0 to html.length)
        else {
            val n = if (allGrids) starts.size else 1
            (0 until n).map { i -> starts[i] to if (i + 1 < starts.size) starts[i + 1] else html.length }
        }
        for ((from, to) in regions) {
            for (block in blocksOf(html, from, to, cardOpen)) {
                val item = parseCardBlock(block) ?: continue
                if (!seen.add(item.id)) continue
                list.add(item)
            }
        }
        if (list.isEmpty()) {
            val m = fallbackLink.matcher(html)
            while (m.find()) {
                val id = m.group(2)
                if (!seen.add(id)) continue
                var name = stripTags(m.group(3)).replace(Regex("全集在线观看\\s*$"), "").trim()
                if (name.isEmpty() || name.matches(Regex("\\d+"))) continue
                list.add(VideoCard(id, name, "", ""))
            }
        }
        return list
    }

    private val rankListOpen = Pattern.compile("<div\\s+class=\"[^\"]*\\bhg-rank-list\\b[^\"]*\"[^>]*>")
    private val rankItemOpen = Pattern.compile("<div\\s+class=\"[^\"]*\\bhg-rank-item\\b[^\"]*\"[^>]*>")
    private val rankTitle = Pattern.compile("hg-rank-item__title[^>]*>([\\s\\S]*?)</h2>")
    private val rankTags = Pattern.compile("hg-rank-item__tags[^>]*>([\\s\\S]*?)</div>")
    private val rankTrackId = Pattern.compile("data-track-id=\"(\\d+)\"")
    private val rankTrackTitle = Pattern.compile("data-track-title=\"([^\"]*)\"")

    private fun parseRanks(html: String): List<VideoCard> {
        if (html.isEmpty()) return emptyList()
        val list = ArrayList<VideoCard>()
        val seen = HashSet<String>()
        val lm = rankListOpen.matcher(html)
        val from = if (lm.find()) lm.end() else 0
        for (block in blocksOf(html, from, html.length, rankItemOpen)) {
            val idM = cardLink.matcher(block)
            val id = if (idM.find()) idM.group(1) else (group(rankTrackId, block, 1) ?: "")
            if (id.isEmpty() || !seen.add(id)) continue
            val imgM = (imgDataSrc.matcher(block).takeIf { it.find() } ?: imgSrc.matcher(block).takeIf { it.find() })
            val tM = rankTitle.matcher(block)
            var title = if (tM.find()) stripTags(tM.group(1)) else ""
            if (title.isEmpty()) {
                val t2 = anyLinkTitle.matcher(block)
                if (t2.find()) title = stripTags(t2.group(1))
            }
            if (title.isEmpty()) title = group(rankTrackTitle, block, 1) ?: ""
            if (title.isEmpty()) continue
            val tgM = rankTags.matcher(block)
            val tags = if (tgM.find()) stripTags(tgM.group(1)) else ""
            list.add(VideoCard(id, title, fix(imgM?.group(1) ?: ""), tags))
        }
        return if (list.isEmpty()) parseGridCards(html, true) else list
    }

    private val h1Re = Pattern.compile("<h1\\b[^>]*>([\\s\\S]*?)</h1>", Pattern.CASE_INSENSITIVE)
    private val titleRe = Pattern.compile("<title\\b[^>]*>([\\s\\S]*?)</title>", Pattern.CASE_INSENSITIVE)

    private fun parseTitle(html: String, fallback: String): String {
        group(h1Re, html, 1)?.let { return stripTags(it) }
        group(titleRe, html, 1)?.let { return stripTags(it).replace(Regex("\\s*[-|｜].*$"), "").trim() }
        return fallback
    }

    private val initialData = Pattern.compile("id=[\"']videoInitialData[\"'][^>]*>([\\s\\S]*?)</script>", Pattern.CASE_INSENSITIVE)
    private val ogImage = Pattern.compile("<meta\\b[^>]*(?:property|name)=\"og:image\"[^>]*content=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE)
    private val detailImg = Pattern.compile("<img\\b[^>]*(?:data-src|src)=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE)

    private fun parsePicRaw(html: String): String {
        group(initialData, html, 1)?.let {
            try {
                val pic = JSONObject(it).optString("coverSrc", "")
                if (pic.isNotEmpty()) return fix(pic)
            } catch (_: Exception) {
            }
        }
        group(ogImage, html, 1)?.let { return fix(it) }
        group(detailImg, html, 1)?.let { return fix(it) }
        return ""
    }

    private val epGrid = Pattern.compile("<div\\s+class=\"[^\"]*\\bhg-web-detail__ep-grid\\b[^\"]*\"[^>]*>([\\s\\S]*?)</div>")
    private val anchorRe = Pattern.compile("<a\\b[^>]*>[\\s\\S]*?</a>", Pattern.CASE_INSENSITIVE)
    private val hrefRe = Pattern.compile("href=\"([^\"]+)\"")
    private val epIdRe = Pattern.compile("data-ep-id=\"([^\"]*)\"")
    private val epNumRe = Pattern.compile("/ep-(\\d+)/?")
    private val digitsRe = Pattern.compile("(\\d+)")

    private fun parseEpisodes(html: String, id: String): List<Episode> {
        val eps = ArrayList<Episode>()
        val seen = HashSet<String>()
        val gridM = epGrid.matcher(html)
        val scope = if (gridM.find()) gridM.group(1) else html
        val am = anchorRe.matcher(scope)
        while (am.find()) {
            val tag = am.group()
            val hm = hrefRe.matcher(tag)
            if (!hm.find()) continue
            val href = fix(hm.group(1))
            if (!href.contains("/video/$id/") && !href.contains("/detail/$id/")) continue
            var ep = group(epIdRe, tag, 1) ?: ""
            if (ep.isEmpty()) ep = group(epNumRe, href, 1) ?: ""
            if (ep.isEmpty()) ep = group(digitsRe, stripTags(tag), 1) ?: ""
            if (ep.isEmpty()) ep = "1"
            if (!seen.add(ep)) continue
            eps.add(Episode(ep, href))
        }
        val vre = Pattern.compile("href=\"([^\"]*/video/$id/(?:ep-(\\d+)/)?)\"")
        val vm = vre.matcher(html)
        while (vm.find()) {
            val ep = vm.group(2) ?: "1"
            if (!seen.add(ep)) continue
            eps.add(Episode(ep, fix(vm.group(1))))
        }
        if (eps.isEmpty()) eps.add(Episode("1", "$SITE/video/$id/"))
        eps.sortBy { it.ep.toIntOrNull() ?: 0 }
        return eps
    }

    private fun normalizePlayUrl(u: String): String {
        if (u.isEmpty()) return ""
        var s = u.replace("\\u0026", "&").replace("\\/", "/").replace("&amp;", "&").trim()
        if (s.startsWith("//")) s = "https:$s"
        else if (s.startsWith("/")) s = SITE + s
        return s
    }

    private val m3u8Escaped = Pattern.compile("https?:\\\\?/\\\\?/[^\"]+?\\.m3u8(?:\\?[^\"'<>\\s]*)?", Pattern.CASE_INSENSITIVE)
    private val m3u8Plain = Pattern.compile("https?://[^\"'<>\\s]+?\\.m3u8(?:\\?[^\"'<>\\s]*)?", Pattern.CASE_INSENSITIVE)

    private fun extractPlay(html: String, ep: String): String {
        var play = ""
        group(initialData, html, 1)?.let {
            try {
                val data = JSONObject(it)
                val srcs = data.optJSONObject("epPlaySrcs")
                play = srcs?.optString(ep, "") ?: ""
                if (play.isEmpty()) play = data.optString("videoSrc", "")
            } catch (_: Exception) {
            }
        }
        play = normalizePlayUrl(play)
        if (!play.startsWith("http")) {
            val m = m3u8Escaped.matcher(html)
            if (m.find()) play = normalizePlayUrl(m.group())
            else {
                val m2 = m3u8Plain.matcher(html)
                if (m2.find()) play = normalizePlayUrl(m2.group())
            }
        }
        return play
    }

    // ---------- 对外接口 ----------

    fun homeVod(): List<VideoCard> = parseGridCards(getHtml("$SITE/"), true)

    fun category(tid: String, page: Int): List<VideoCard> {
        val id = tid.trim('/')
        val url = "$SITE/$id/" + if (page > 1) "$page/" else ""
        val html = getHtml(url)
        return if (tid.contains("rank")) parseRanks(html) else parseGridCards(html, false)
    }

    fun search(key: String, page: Int): List<VideoCard> {
        val url = "$SITE/search/video/${android.net.Uri.encode(key)}/" + if (page > 1) "$page/" else ""
        return parseGridCards(getHtml(url), false)
    }

    fun detail(id: String): VideoDetail {
        val html = getHtml("$SITE/video/$id/", "$SITE/")
        return VideoDetail(id, parseTitle(html, id), parsePicRaw(html), parseEpisodes(html, id))
    }

    // ---------- 播放地址：JSON API（xptv huangguo.js 同步） + 加密边缘通道兜底 ----------

    private val videoIdRe = Regex("/(?:video|detail)/(\\d+)/")

    private val jsonClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    private fun postJson(url: String, body: String, referer: String): JSONObject? {
        val req = Request.Builder().url(url)
            .post(body.toRequestBody("application/json".toMediaType()))
            .header("User-Agent", UA)
            .header("Accept", "application/json, text/plain, */*")
            .header("Origin", SITE)
            .header("Referer", referer)
            .build()
        return try {
            jsonClient.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return null
                JSONObject(resp.body?.string() ?: "")
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun pickStreams(j: JSONObject?): String {
        val streams = j?.optJSONObject("data")?.optJSONObject("streams") ?: return ""
        return streams.optString("main", "").ifEmpty { streams.optString("hevc", "") }
    }

    private fun apiPlayback(id: String, ep: String, referer: String): String {
        if (id.isEmpty()) return ""
        val j = postJson("$SITE/api/videos/$id/episodes/$ep/playback", "{}", referer) ?: return ""
        return normalizePlayUrl(pickStreams(j))
    }

    // ---- dx150-edge-v1：P-256 ECDH + HKDF-SHA256 + AES-256-GCM ----

    private val b64urlEnc = Base64.getUrlEncoder().withoutPadding()
    private val b64urlDec = Base64.getUrlDecoder()
    private val b64StdDec = Base64.getDecoder()

    private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, len: Int): ByteArray {
        val prk = macSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        val out = ByteArray(len)
        var prev = ByteArray(0)
        var filled = 0
        var counter = 1
        while (filled < len) {
            prev = macSha256(prk, prev + info + byteArrayOf(counter.toByte()))
            val n = minOf(prev.size, len - filled)
            System.arraycopy(prev, 0, out, filled, n)
            filled += n
            counter++
        }
        return out
    }

    private fun macSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun edgePost(body: String, referer: String): JSONObject? =
        postJson("$SITE/api/playback/request", body, referer)

    private fun edgePlayback(id: String, ep: String, referer: String): String {
        if (id.isEmpty()) return ""
        return try {
            val site = hello.optString("site", SITE.removePrefix("https://")) // KDF info 必须用服务端下发的 site
            // hello
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            val kp = kpg.genKeyPair()
            val pub = kp.public as ECPublicKey
            val p = pub.w
            val pubBytes = byteArrayOf(4) +
                toFixed32(p.affineX) + toFixed32(p.affineY)
            val clientPub = b64urlEnc.encodeToString(pubBytes)
            val hello = edgePost(
                JSONObject().put("v", 1).put("type", "hello").put("client_pub", clientPub).toString(),
                referer
            ) ?: return ""
            if (hello.optInt("v") != 1 || hello.optString("type") != "hello") return ""
            val kid = hello.optString("kid")
            val sid = hello.optString("sid")
            val serverPub = b64urlDec.decode(hello.optString("server_pub"))
            val salt = b64urlDec.decode(hello.optString("salt"))
            if (salt.size != 32 || serverPub.size != 65 || serverPub[0] != 4.toByte()) return ""
            // ECDH
            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(kp.private)
            val srvPoint = ECPoint(BigInteger(1, serverPub.copyOfRange(1, 33)), BigInteger(1, serverPub.copyOfRange(33, 65)))
            val srvKey = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(srvPoint, pub.params))
            ka.doPhase(srvKey, true)
            val shared = ka.generateSecret() // 32 字节 X 坐标
            val infoStr = "dx150-edge-v1\nplayback\n$site\n$kid\n$sid"
            val reqKey = hkdfSha256(shared, salt, (infoStr + "\nreq").toByteArray(Charsets.UTF_8), 32)
            val resKey = hkdfSha256(shared, salt, (infoStr + "\nres").toByteArray(Charsets.UTF_8), 32)
            val offset = (hello.optLong("server_time", 0) - System.currentTimeMillis() / 1000)
            // call
            val seq = 1
            val ts = System.currentTimeMillis() / 1000 + offset
            val iv = ByteArray(12)
            iv[8] = (seq ushr 24).toByte(); iv[9] = (seq ushr 16).toByte()
            iv[10] = (seq ushr 8).toByte(); iv[11] = seq.toByte()
            val inner = JSONObject().put("request", JSONObject()
                .put("method", "POST")
                .put("path", "/api/videos/$id/episodes/$ep/playback")
                .put("body", b64urlEnc.encodeToString("{}".toByteArray(Charsets.UTF_8)))
                .put("content_type", "application/json")
                .put("visitor_id", randomHex(16))
                .put("channel_code", ""))
            val aadReq = (infoStr + "\nreq\n" + seq + "\n" + ts).toByteArray(Charsets.UTF_8)
            val ct = gcmEncrypt(reqKey, iv, aadReq, inner.toString().toByteArray(Charsets.UTF_8))
            val callBody = JSONObject()
                .put("v", 1).put("type", "call").put("kid", kid).put("sid", sid)
                .put("seq", seq).put("ts", ts)
                .put("ciphertext", b64urlEnc.encodeToString(ct))
                .toString()
            val res = edgePost(callBody, referer) ?: return ""
            if (res.optInt("v") != 1 || res.optString("type") != "result" ||
                res.optString("sid") != sid || res.optInt("seq") != seq) return ""
            val aadRes = (infoStr + "\nres\n" + seq + "\n" + ts).toByteArray(Charsets.UTF_8)
            val pt = gcmDecrypt(resKey, iv, aadRes, b64urlDec.decode(res.optString("ciphertext")))
            val innerRes = JSONObject(String(pt, Charsets.UTF_8))
            val text = if (innerRes.optString("body").isNotEmpty())
                String(b64StdDec.decode(innerRes.optString("body")), Charsets.UTF_8) else ""
            normalizePlayUrl(pickStreams(JSONObject(text)))
        } catch (_: Exception) {
            ""
        }
    }

    private fun toFixed32(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        return if (b.size == 32) b
        else if (b.size > 32) b.copyOfRange(b.size - 32, b.size)
        else ByteArray(32 - b.size) + b
    }

    private fun randomHex(n: Int): String {
        val b = ByteArray(n)
        SecureRandom().nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }

    private fun gcmEncrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        if (aad.isNotEmpty()) c.updateAAD(aad)
        return c.doFinal(plain) // 密文 || tag，与服务端 ct||tag 约定一致
    }

    private fun gcmDecrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, data: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        if (aad.isNotEmpty()) c.updateAAD(aad)
        return c.doFinal(data)
    }

    fun play(pageUrl: String, ep: String): String {
        val id = videoIdRe.find(pageUrl)?.groupValues?.get(1) ?: ""
        val referer = "$SITE/video/$id/"
        // 1) 明文 JSON API
        apiPlayback(id, ep, referer).takeIf { it.startsWith("http") }?.let { return it }
        // 2) 加密边缘通道（明文 API 关闭后兜底）
        edgePlayback(id, ep, referer).takeIf { it.startsWith("http") }?.let { return it }
        // 3) 旧版页面抓取兜底
        return extractPlay(getHtml(fix(pageUrl), "$SITE/"), ep)
    }
}
