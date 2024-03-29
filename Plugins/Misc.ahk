﻿; RunZ:Misc
; 实用工具集合

Misc:
    @("Dictionary", "有道词典在线翻译")
    @("Calc", "计算器")
    @("SearchOnGoogle", "使用 谷歌 搜索剪切板或输入内容")
    @("SearchOnBaidu", "使用 百度 搜索剪切板或输入内容")
    @("SearchOnZhihu", "使用 知乎 搜索剪切板或输入内容")
    @("SearchOnNpm", "使用 npm 搜索剪切板或输入内容")
    @("SearchOnGithub", "使用 github 搜索剪切板或输入内容")
    @("SearchOnBing", "使用 必应 搜索剪切板或输入内容")
    @("SearchOnTaobao", "使用 淘宝 搜索剪切板或输入内容")
    @("SearchOnJD", "使用 京东 搜索剪切板或输入内容")
    @("ShowIp", "显示 IP")
    @("Calendar", "用浏览器打开万年历")
    @("CurrencyRate", "汇率 使用示例： hl JPY EUR 2")
    @("CNY2USD", "汇率 人民币兑换美元")
    @("USD2CNY", "汇率 美元兑换人民币")
    @("UrlEncode", "URL 编码")
return

CNY2USD:
    DisplayResult("查询中，可能会比较慢或者查询失败，请稍后...")
    DisplayResult(QueryCurrencyRate("CNY", "USD", Arg))
return

USD2CNY:
    DisplayResult("查询中，可能会比较慢或者查询失败，请稍后...")
    DisplayResult(QueryCurrencyRate("USD", "CNY", Arg))
return

CurrencyRate:
    args := StrSplit(Arg, " ")
    if (args.Length() != 3)
    {
        DisplayResult("使用示例：`n    CurrencyRate USD CNY 2")
        return
    }

    DisplayResult("查询中，可能会比较慢或者查询失败，请稍后...")
    DisplayResult(QueryCurrencyRate(args[1], args[2], args[3]))
return

QueryCurrencyRate(fromCurrency, toCurrency, amount)
{
    headers := Object()
    headers["apikey"] := "c9098c96599be340bbd9551e2b061f63"

    jsonText := UrlDownloadToString("http://apis.baidu.com/apistore/currencyservice/currency?"
        . "fromCurrency=" fromCurrency "&toCurrency=" toCurrency "&amount=" amount, headers)
    parsed := JSON.Load(jsonText)

    if (parsed.errNum != 0 && parsed.errMsg != "success")
    {
        return "查询失败，错误信息：`n`n" jsonText
    }

    result := fromCurrency " 兑换 " toCurrency " 当前汇率：`n`n" parsed.retData.currency "`n`n`n"
    result .= amount " " fromCurrency " = " parsed.retData.convertedamount " " toCurrency "`n"

    return result
}

ShowIp:
    DisplayResult(A_IPAddress1
            . "`r`n" . A_IPAddress2
            . "`r`n" . A_IPAddress3
            . "`r`n" . A_IPAddress4)
return

Dictionary:
    word := Arg == "" ? clipboard : Arg

    BaiduFanyiAPI(keyword, from:="auto", to:="zh") {
        appId := "*****" ; 请替换为您的APP ID
        key := "******" ; 请替换为您的密钥
        salt := A_Now
        MD5Sign := MD5(appId keyword salt key)
        ; keyword := UrlEncode(keyword)
        URL := Format("https://fanyi-api.baidu.com/api/trans/vip/translate?q={1}&from={2}&to={3}&appid={4}&salt={5}&sign={6}", keyword, from, to, appId, salt, MD5Sign)
        WebRequest := ComObjCreate("WinHttp.WinHttpRequest.5.1")
        WebRequest.Open("GET", url)
        WebRequest.Send()
        result := WebRequest.ResponseText
        result := JSON.load(result)
        return result["trans_result"][1]["dst"]
    }

    isEnglish(text) {
        ; Regular expression pattern for English characters (A-Z, a-z)
        pattern := "^[A-Za-z]+$"
        return RegExMatch(text, pattern)
    }

    YouDaoFanyiAPi() {
        url := "http://fanyi.youdao.com/openapi.do?keyfrom=YouDaoCV&key=659600698&"
        . "type=data&doctype=json&version=1.2&q=" UrlEncode(word)

        jsonText := StrReplace(UrlDownloadToString(url), "-phonetic", "_phonetic")

        if (jsonText == "no query")
        {
            DisplayResult("未查到结果")
            return
        }

        parsed := JSON.Load(jsonText)
        result := parsed.query

        if (parsed.basic.uk_phonetic != "" && parsed.basic.us_phonetic != "")
        {
            result .= " UK: [" parsed.basic.uk_phonetic "], US: [" parsed.basic.us_phonetic "]`n"
        }
        else if (parsed.basic.phonetic != "")
        {
            result .= " [" parsed.basic.phonetic "]`n"
        }
        else
        {
            result .= "`n"
        }

        if (parsed.basic.explains.Length() > 0)
        {
            result .= "`n"
            for index, explain in parsed.basic.explains
            {
                result .= " * " explain "`n"
            }
        }

        if (parsed.web.Length() > 0)
        {
            result .= "`n----`n"

            for i, element in parsed.web
            {
                result .= "`n * " element.key
                for j, value in element.value
                {
                    if (j == 1)
                    {
                        result .= "`n "
                    }
                    else
                    {
                        result .= "`; "
                    }

                    result .= value
                }
            }
        }
        return result
    }

    EncodeDecodeURI(str, encode := true, component := true) {
        static Doc, JS
        if !Doc {
            Doc := ComObjCreate("htmlfile")
            Doc.write("<meta http-equiv=""X-UA-Compatible"" content=""IE=9"">")
            JS := Doc.parentWindow
            ( Doc.documentMode < 9 && JS.execScript() )
        }
        Return JS[ (encode ? "en" : "de") . "codeURI" . (component ? "Component" : "") ](str)
    }

    BingExtract(html) {
        keywordsRegex := "<meta name=""keywords"" content=""(.*?)"" />"
        descriptionRegex := "i)<meta name=""description"" (content=""(.*?)"") />"
        keywordsMatch := RegExMatch(html, keywordsRegex, keywords)
        descriptionMatch := RegExMatch(html, descriptionRegex, description)

        result := ""

        if descriptionMatch {
            ; MsgBox % "Description: " . description
            if RegExMatch(description, "i)，(.*?)""", description){
                clipboard := description
                ; MsgBox % SubStr(a, 2, -1)
                data := StrSplit(SubStr(description, 2, -1), "，")
                if data.Length() == 2 {
                    result .= data[1] . "`n`n" . data[2]
                } else {
                    result .= data[1] . " " . data[2] . "`n`n" . data[3]
                }
            }
        } else {
            result = "not found"
        }
        return result
    }

    BingFanyi(word){
        url := "https://cn.bing.com/dict/search?q=" . EncodeDecodeURI(word)

        httpRequest := ComObjCreate("WinHttp.WinHttpRequest.5.1")
        httpRequest.Open("GET", url)
        httpRequest.Send()

        responseBody := httpRequest.ResponseText

        ; return BingExtract(SubStr(responseBody, 1, 2000))

        html := ComObjCreate("HTMLFile")
        html.write(responseBody)

        div := html.getElementsByTagName("div")

        ;翻译
        result .= div[14].innerText
        return SubStr(result, StrLen(word)+3)
    }

    YouDaoFanyi(word){
        url := "https://www.youdao.com/result?lang=en&word=" . EncodeDecodeURI(word)
        httpRequest := ComObjCreate("WinHttp.WinHttpRequest.5.1")
        httpRequest.Open("GET", url)
        httpRequest.Send()

        HtmlText := httpRequest.ResponseText

        html := ComObjCreate("HTMLFile")
        html.write(SubStr(HtmlText, 30000))

        ul := html.getElementsByTagName("ul")
        span := html.getElementsByTagName("span")

        result := ""
        ;音标
        result .= span[17].innerText . " " . span[18].innerText . " " . span[19].innerText . " " . span[20].innerText  . "`n"
        ;翻译
        result .= ul[5].innerText . "`n"
        ;语法
        ; result .= html.getElementsByTagName("ul")[6].innerText . " "
        ; network
        result .= ul[8].innerText . "`n"
        ; phrase
        result .= ul[9].innerText . "`n"
        result .= ul[11].innerText . "`n"
        result .= ul[13].innerText . "`n"
        return result
    }

    ; sourceText := word
    ; fromLanguage := "auto"
    ; toLanguage := isEnglish(sourceText) ? "zh" : "en"
    ; result := BaiduFanyiAPI(sourceText, fromLanguage, toLanguage)

    ; result := YouDaoFanyi(word)
    result := BingFanyi(word)
    DisplayResult(result)
    ; clipboard := result
return


Calendar:
    Run % "http://www.baidu.com/baidu?wd=%CD%F2%C4%EA%C0%FA"
return

SearchOnBaidu:
    word := Arg == "" ? clipboard : Arg

    Run, https://www.baidu.com/s?wd=%word%
return

SearchOnZhihu:
    word := Arg == "" ? clipboard : Arg

    Run, https://www.zhihu.com/search?type=content&q=%word%
return

SearchOnNpm:
    word := Arg == "" ? clipboard : Arg

    Run, https://www.npmjs.com/search?q=%word%
return

SearchOnGithub:
    word := Arg == "" ? clipboard : Arg

    Run, https://github.com/search?q=%word%
return

SearchOnGoogle:
    word := UrlEncode(Arg == "" ? clipboard : Arg)

    Run, https://www.google.com/search?q=%word%
return

SearchOnBing:
    word := Arg == "" ? clipboard : Arg

    Run, http://cn.bing.com/search?q=%word%
return

SearchOnTaobao:
    word := Arg == "" ? clipboard : Arg

    Run, https://s.taobao.com/search?q=%word%
return

SearchOnJD:
    word := Arg == "" ? clipboard : Arg

    Run, http://search.jd.com/Search?keyword=%word%&enc=utf-8
return

Calc:
    result := Eval(Arg)
    DisplayResult(result)
    clipboard := result
    TurnOnRealtimeExec()
return

UrlEncode:
    text := Arg == "" ? clipboard : Arg
    clipboard := UrlEncode(text)
    DisplayResult(clipboard)
return


#include %A_ScriptDir%\Lib\Eval.ahk
#include %A_ScriptDir%\Lib\JSON.ahk
