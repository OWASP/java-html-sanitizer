package org.owasp.html.examples;

import org.owasp.html.AttributePolicy;
import org.owasp.html.CssSchema;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

public class NaverPolicyExample {

  private static String[] mdnGlobalAttributeArray = {"accesskey", "class", "dir", "exportparts", "hidden", "id", "lang", "style", "tabindex", "title"}; // exclude attribute : autocapitalize contenteditable contextmenu data-* draggable dropzone inputmode is itemid itemprop itemref itemscope itemtype part slot spellcheck translate
  private static String[] aDefaultAttributeArray = {"charset", "coords", "href", "hreflang", "name", "rel", "rev", "shape", "target", "type"}; // exclude attribute : media

  // abbr(only include global attributes)
  // acronym(only include global attributes)
  // address(only include global attributes)

  private static String[] appletDefaultAttributeArray = {"code", "object", "align", "alt", "archive", "codebase", "height", "hspace", "name", "vspace", "width", "src"}; // exclude attribute : datafld, datasrc, mayscript
  private static String[] areaDefaultAttributeArray = {"alt", "coords", "href", "hreflang", "nohref", "rel", "shape", "target", "type", "name", "tabindex"}; // exclude attribute : download, ping, referrerpolicy, media

  // article(only include global attributes)
  // aside(only include global attributes)

  private static String[] audioDefaultAttributeArray = {"autoplay", "controls", "loop", "muted", "preload", "src"}; // exclude attribute : crossorigin, currentTime, disableRemotePlayback, duration

  // b(only include global attributes)
  // base(exclude element)

  private static String[] basefontDefaultAttributeArray = {"color", "face", "size"};

  // bb(exclude element)
  // bdi(only include global attributes)

  private static String[] bdoDefaultAttributeArray = {"dir"};

  // bgsound(exclude element)
  // big(only include global attributes)
  // blink(exclude element)

  private static String[] blockquoteDefaultAttributeArray = {"cite"};

  // body(exclude element)
  // br(only include global attributes)

  private static String[] buttonDefaultAttributeArray = {"autofocus", "disabled", "form", "formenctype", "formmethod", "formnovalidate", "formtarget", "name", "type", "value", "autocomplete"}; // exclude attribute : formaction
  private static String[] canvasDefaultAttributeArray = {"height", "width"}; // exclude attribute : moz-opaque
  private static String[] captionDefaultAttributeArray = {"align"};

  // center(don't include any attribute. but not exclude element)
  // cite(only include global attributes)
  // code(only include global attributes)

  private static String[] colDefaultAttributeArray = {"align", "char", "charoff", "span", "valign", "width", "bgcolor"};
  private static String[] colgroupDefaultAttributeArray = {"align", "char", "charoff", "span", "valign", "bgcolor"};

  // command(exclude element)
  // content(exclude element)
  // data(exclude element)
  // datagrid(exclude element)
  // datalist(only include global attributes)

  private static String[] ddDefaultAttributeArray = {"nowrap"};
  private static String[] delDefaultAttributeArray = {"cite", "datetime"};
  private static String[] detailsDefaultAttributeArray = {"open"};

  // dfn(only include global attributes)
  // dialog(exclude element)
  // dir(exclude element)
  // div(only include global attributes)
  // dl(only include global attributes)
  // dt(only include global attributes)
  // element(exclude element)
  // em(only include global attributes)
  // embed(exclude element)

  private static String[] fieldsetDefaultAttributeArray = {"disabled", "form", "name"};

  // figcaption(only include global attributes)
  // figure(only include global attributes)

  private static String[] fontDefaultAttributeArray = {"color", "face", "size"};

  // footer(only include global attributes)

  private static String[] formDefaultAttributeArray = {"accept", "accept-charset", "action", "autocomplete", "enctype", "method", "name", "novalidate", "target", "rel"}; // exclude attribute : autocapitalize
  private static String[] frameDefaultAttributeArray = {"frameborder", "marginheight", "marginwidth", "name", "noresize", "scrolling", "src"};
  private static String[] framesetDefaultAttributeArray = {"cols", "rows"};

  // h1-h6(only include global attributes)

  private static String[] headDefaultAttributeArray = {"profile"};

  // header(only include global attributes)
  // hgroup(only include global attributes)

  private static String[] hrDefaultAttributeArray = {"align", "noshade", "size", "width", "color"};
  private static String[] htmlDefaultAttributeArray = {"manifest", "version"}; // exclude attribute : xmlns

  // i(only include global attributes)
  // iframe(exclude element)

  private static String[] imgDefaultAttributeArray = {"align", "alt", "border", "height", "hspace", "ismap", "longdesc", "sizes", "src", "usemap", "vspace", "width", "name"}; // exclude attribute : crossorigin, srcset, decoding, importance, intrinsicsize, loading, referrerpolicy
  private static String[] inputDefaultAttributeArray = {"accept", "alt", "autocomplete", "autofocus", "checked", "disabled", "form", "formenctype", "formmethod",
          "formnovalidate", "formtarget", "height", "list", "max", "maxlength", "min", "multiple", "name", "pattern", "placeholder", "readonly", "required", "size",
          "src", "step", "type", "value", "width", "tabindex", "title"}; // exclude attribute : dirname, formaction, capture, inputmode, minlength, autocorrect, incremental, mozactionhint, orient, results, webkitdirectory
  private static String[] insDefaultAttributeArray = {"cite", "datetime"};

  // isindex(exclude element)
  // kbd(only include global attributes)

  private static String[] keygenDefaultAttributeArray = {"autofocus", "challenge", "disabled", "form", "keytype", "name"};
  private static String[] labelDefaultAttributeArray = {"for", "form"};

  // legend(only include global attributes)

  private static String[] liDefaultAttributeArray = {"type", "value"};

  // link(exclude element)
  // listing(exclude element)
  // main(exclude element)

  private static String[] mapDefaultAttributeArray = {"name"};

  // mark(only include global attributes)

  private static String[] marqueeDefaultAttributeArray = {"width", "height", "direction", "behavior", "scrolldelay", "scrollamount", "bgcolor", "hspace", "vspace", "loop"}; // exclude attribute : truespeed
  private static String[] menuDefaultAttributeArray = {"type", "label"};

  // menuitem(exclude element)
  // meta(exclude element)

  private static String[] meterDefaultAttributeArray = {"form", "high", "low", "max", "min", "optimum", "value"};

  // multicol(exclude element)
  // nav(only include global attributes)
  // nobr(don't include any attribute. but not exclude element)
  // noembed(exclude element)
  // noframes(only include global attributes)
  // noscript(only include global attributes)
  // object(exclude element)

  private static String[] olDefaultAttributeArray = {"start", "type"}; // exclude attribute : reversed
  private static String[] optgroupDefaultAttributeArray = {"disabled", "label"};
  private static String[] optionDefaultAttributeArray = {"disabled", "label", "selected", "value"};
  private static String[] outputDefaultAttributeArray = {"for", "form", "name"};

  // p(only include global attributes)

  private static String[] paramDefaultAttributeArray = {"name", "type", "value", "valuetype"};

  // picture(exclude element)
  // plaintext(exclude element)

  private static String[] preDefaultAttributeArray = {"width", "cols", "wrap"};
  private static String[] progressDefaultAttributeArray = {"max", "value"};
  private static String[] qDefaultAttributeArray = {"cite"};

  // rp(only include global attributes)
  // rt(only include global attributes)
  // rtc(exclude element)
  // ruby(only include global attributes)
  // s(only include global attributes)
  // samp(only include global attributes)
  // script(exclude element)
  // section(only include global attributes)

  private static String[] selectDefaultAttributeArray = {"autofocus", "disabled", "form", "multiple", "name", "required", "size", "autocomplete"};

  // shadow(exclude element)
  // slot(exclude element)
  // small(only include global attributes)

  private static String[] sourceDefaultAttributeArray = {"src", "media", "sizes", "type"}; // exclude attribute : srcset

  // spacer(exclude element)
  // span(only include global attributes)
  // strike(only include global attributes)
  // strong(only include global attributes)
  // style(exclude element)
  // sub(only include global attributes)
  // summary(only include global attributes)
  // sup(only include global attributes)
  // svg(exclude element)

  private static String[] tableDefaultAttributeArray = {"align", "bgcolor", "border", "cellpadding", "cellspacing", "frame", "rules", "summary", "width"};
  private static String[] tbodyDefaultAttributeArray = {"align", "char", "charoff", "valign", "bgcolor"};
  private static String[] tdDefaultAttributeArray = {"abbr", "align", "axis", "bgcolor", "char", "charoff", "colspan", "headers", "height", "rowspan", "scope", "valign", "width"};

  // template(exclude element)

  private static String[] textareaDefaultAttributeArray = {"autofocus", "cols", "disabled", "form", "maxlength", "name", "placeholder", "readonly", "required", "rows", "wrap", "autocomplete"}; // exclude attribute : dirname, autocapitalize, minlength, spellcheck
  private static String[] tfootDefaultAttributeArray = {"align", "char", "charoff", "valign", "bgcolor"};
  private static String[] thDefaultAttributeArray = {"abbr", "align", "axis", "bgcolor", "char", "charoff", "colspan", "headers", "height", "rowspan", "scope", "valign", "width"};
  private static String[] theadDefaultAttributeArray = {"align", "char", "charoff", "valign", "bgcolor"};
  private static String[] timeDefaultAttributeArray = {"datetime"};

  // title(only include global attributes)

  private static String[] trDefaultAttributeArray = {"align", "bgcolor", "char", "charoff", "valign"};
  private static String[] trackDefaultAttributeArray = {"default", "kind", "label", "src", "srclang"};

  // tt(only include global attributes)
  // u(only include global attributes)

  private static String[] ulDefaultAttributeArray = {"compact", "type"};

  // var(only include global attributes)

  private static String[] videoDefaultAttributeArray = {"autoplay", "controls", "height", "loop", "muted", "poster", "preload", "src", "width"}; // exclude attribute : autoPictureInPicture buffered controlslist crossorigin currentTime disablePictureInPicture disableRemotePlayback duration intrinsicsize playsinline

  // wbr(only include global attributes)
  // xmp(only include global attributes)
  // xcustom(exclude element)

  public static final PolicyFactory POLICY_DEFINITION;

  static {
    // a
    String[] aAttributeArray = appendGlobalAttributes(aDefaultAttributeArray);
    // area
    String[] areaAttributeArray = appendGlobalAttributes(areaDefaultAttributeArray);
    // audio
    String[] audioAttributeArray = appendGlobalAttributes(audioDefaultAttributeArray);
    // basefont
    String[] basefontAttributeArray = appendGlobalAttributes(basefontDefaultAttributeArray);
    // bdo
    String[] bdoAttributeArray = appendGlobalAttributes(bdoDefaultAttributeArray);
    // blockquote
    String[] blockquoteAttributeArray = appendGlobalAttributes(blockquoteDefaultAttributeArray);
    // button
    String[] buttonAttributeArray = appendGlobalAttributes(buttonDefaultAttributeArray);
    // canvas
    String[] canvasAttributeArray = appendGlobalAttributes(canvasDefaultAttributeArray);
    // caption
    String[] captionAttributeArray = appendGlobalAttributes(captionDefaultAttributeArray);
    // col
    String[] colAttributeArray = appendGlobalAttributes(colDefaultAttributeArray);
    // colgroup
    String[] colgroupAttributeArray = appendGlobalAttributes(colgroupDefaultAttributeArray);
    // dd
    String[] ddAttributeArray = appendGlobalAttributes(ddDefaultAttributeArray);
    // del
    String[] delAttributeArray = appendGlobalAttributes(delDefaultAttributeArray);
    // details
    String[] detailsAttributeArray = appendGlobalAttributes(detailsDefaultAttributeArray);
    // fieldset
    String[] fieldsetAttributeArray = appendGlobalAttributes(fieldsetDefaultAttributeArray);
    // font
    String[] fontAttributeArray = appendGlobalAttributes(fontDefaultAttributeArray);
    // form
    String[] formAttributeArray = appendGlobalAttributes(formDefaultAttributeArray);
    // frame
    String[] frameAttributeArray = appendGlobalAttributes(frameDefaultAttributeArray);
    // frameset
    String[] framesetAttributeArray = appendGlobalAttributes(framesetDefaultAttributeArray);
    // head
    String[] headAttributeArray = appendGlobalAttributes(headDefaultAttributeArray);
    // hr
    String[] hrAttributeArray = appendGlobalAttributes(hrDefaultAttributeArray);
    // html
    String[] htmlAttributeArray = appendGlobalAttributes(htmlDefaultAttributeArray);
    // img
    String[] imgAttributeArray = appendGlobalAttributes(imgDefaultAttributeArray);
    // input
    String[] inputAttributeArray = appendGlobalAttributes(inputDefaultAttributeArray);
    // ins
    String[] insAttributeArray = appendGlobalAttributes(insDefaultAttributeArray);
    // keygen
    String[] keygenAttributeArray = appendGlobalAttributes(keygenDefaultAttributeArray);
    // label
    String[] labelAttributeArray = appendGlobalAttributes(labelDefaultAttributeArray);
    // li
    String[] liAttributeArray = appendGlobalAttributes(liDefaultAttributeArray);
    // map
    String[] mapAttributeArray = appendGlobalAttributes(mapDefaultAttributeArray);
    // menu
    String[] menuAttributeArray = appendGlobalAttributes(menuDefaultAttributeArray);
    // meter
    String[] meterAttributeArray = appendGlobalAttributes(meterDefaultAttributeArray);
    // ol
    String[] olAttributeArray = appendGlobalAttributes(olDefaultAttributeArray);
    // optgroup
    String[] optgroupAttributeArray = appendGlobalAttributes(optgroupDefaultAttributeArray);
    // option
    String[] optionAttributeArray = appendGlobalAttributes(optionDefaultAttributeArray);
    // output
    String[] outputAttributeArray = appendGlobalAttributes(outputDefaultAttributeArray);
    // param
    String[] paramAttributeArray = appendGlobalAttributes(paramDefaultAttributeArray);
    // pre
    String[] preAttributeArray = appendGlobalAttributes(preDefaultAttributeArray);
    // progress
    String[] progressAttributeArray = appendGlobalAttributes(progressDefaultAttributeArray);
    // q
    String[] qAttributeArray = appendGlobalAttributes(qDefaultAttributeArray);
    // select
    String[] selectAttributeArray = appendGlobalAttributes(selectDefaultAttributeArray);
    // source
    String[] sourceAttributeArray = appendGlobalAttributes(sourceDefaultAttributeArray);
    // table
    String[] tableAttributeArray = appendGlobalAttributes(tableDefaultAttributeArray);
    // tbody
    String[] tbodyAttributeArray = appendGlobalAttributes(tbodyDefaultAttributeArray);
    // td
    String[] tdAttributeArray = appendGlobalAttributes(tdDefaultAttributeArray);
    // textarea
    String[] textareaAttributeArray = appendGlobalAttributes(textareaDefaultAttributeArray);
    // tfoot
    String[] tfootAttributeArray = appendGlobalAttributes(tfootDefaultAttributeArray);
    // th
    String[] thAttributeArray = appendGlobalAttributes(thDefaultAttributeArray);
    // thead
    String[] theadAttributeArray = appendGlobalAttributes(theadDefaultAttributeArray);
    // time
    String[] timeAttributeArray = appendGlobalAttributes(timeDefaultAttributeArray);
    // tr
    String[] trAttributeArray = appendGlobalAttributes(trDefaultAttributeArray);
    // track
    String[] trackAttributeArray = appendGlobalAttributes(trackDefaultAttributeArray);
    // ul
    String[] ulAttributeArray = appendGlobalAttributes(ulDefaultAttributeArray);
    // video
    String[] videoAttributeArray = appendGlobalAttributes(videoDefaultAttributeArray);

    POLICY_DEFINITION = new HtmlPolicyBuilder()

            .allowElements("a")
            .allowAttributes(aAttributeArray).onElements("a")
            .disallowAttributes("style").onElements("a")

            .allowElements("abbr")
            .allowAttributes(mdnGlobalAttributeArray).onElements("abbr")

            .allowElements("acronym")
            .allowAttributes(mdnGlobalAttributeArray).onElements("acronym")

            .allowElements("address")
            .allowAttributes(mdnGlobalAttributeArray).onElements("address")

            .allowElements("applet")
            .allowAttributes(appletDefaultAttributeArray).onElements("applet")
            .disallowAttributes("style").onElements("applet")

            .allowElements("area")
            .allowAttributes(areaAttributeArray).onElements("area")

            .allowElements("article")
            .allowAttributes(mdnGlobalAttributeArray).onElements("article")

            .allowElements("aside")
            .allowAttributes(mdnGlobalAttributeArray).onElements("aside")

            .allowElements("audio")
            .allowAttributes(audioAttributeArray).onElements("audio")

            .allowElements("b")
            .allowAttributes(mdnGlobalAttributeArray).onElements("b")

            .allowElements("basefont")
            .allowAttributes(basefontAttributeArray).onElements("basefont")

            .allowElements("bdi")
            .allowAttributes(mdnGlobalAttributeArray).onElements("bdi")

            .allowElements("bdo")
            .allowAttributes(bdoAttributeArray).onElements("bdo")

            .allowElements("big")
            .allowAttributes(mdnGlobalAttributeArray).onElements("big")

            .allowElements("blockquote")
            .allowAttributes(blockquoteAttributeArray).onElements("blockquote")

            .allowElements("br")
            .allowAttributes(mdnGlobalAttributeArray).onElements("br")

            .allowElements("button")
            .allowAttributes(buttonAttributeArray).onElements("button")

            .allowElements("canvas")
            .allowAttributes(canvasAttributeArray).onElements("canvas")

            .allowElements("caption")
            .allowAttributes(captionAttributeArray).onElements("caption")

            .allowElements("center")

            .allowElements("cite")
            .allowAttributes(mdnGlobalAttributeArray).onElements("cite")

            .allowElements("code")
            .allowAttributes(mdnGlobalAttributeArray).onElements("code")

            .allowElements("col")
            .allowAttributes(colAttributeArray).onElements("col")

            .allowElements("colgroup")
            .allowAttributes(colgroupAttributeArray).onElements("colgroup")

            .allowElements("datalist")
            .allowAttributes(mdnGlobalAttributeArray).onElements("datalist")

            .allowElements("dd")
            .allowAttributes(ddAttributeArray).onElements("dd")

            .allowElements("del")
            .allowAttributes(delAttributeArray).onElements("del")

            .allowElements("details")
            .allowAttributes(detailsAttributeArray).onElements("details")

            .allowElements("dfn")
            .allowAttributes(mdnGlobalAttributeArray).onElements("dfn")

            .allowElements("div")
            .allowAttributes(mdnGlobalAttributeArray).onElements("div")

            .allowElements("dl")
            .allowAttributes(mdnGlobalAttributeArray).onElements("dl")

            .allowElements("dt")
            .allowAttributes(mdnGlobalAttributeArray).onElements("dt")

            .allowElements("em")
            .allowAttributes(mdnGlobalAttributeArray).onElements("em")

            .allowElements("fieldset")
            .allowAttributes(fieldsetAttributeArray).onElements("fieldset")

            .allowElements("figcaption")
            .allowAttributes(mdnGlobalAttributeArray).onElements("figcaption")

            .allowElements("figure")
            .allowAttributes(mdnGlobalAttributeArray).onElements("figure")

            .allowElements("font")
            .allowAttributes(fontAttributeArray).onElements("font")

            .allowElements("footer")
            .allowAttributes(mdnGlobalAttributeArray).onElements("footer")

            .allowElements("form")
            .allowAttributes(formAttributeArray).onElements("form")

            .allowElements("frame")
            .allowAttributes(frameAttributeArray).onElements("frame")

            .allowElements("frameset")
            .allowAttributes(framesetAttributeArray).onElements("frameset")

            .allowElements("h1", "h2", "h3", "h4", "h5", "h6")
            .allowAttributes(mdnGlobalAttributeArray).onElements("h1", "h2", "h3", "h4", "h5", "h6")

            .allowElements("head")
            .allowAttributes(headAttributeArray).onElements("head")

            .allowElements("header")
            .allowAttributes(mdnGlobalAttributeArray).onElements("header")

            .allowElements("hgroup")
            .allowAttributes(mdnGlobalAttributeArray).onElements("hgroup")

            .allowElements("hr")
            .allowAttributes(hrAttributeArray).onElements("hr")

            .allowElements("html")
            .allowAttributes(htmlAttributeArray).onElements("html")

            .allowElements("i")
            .allowAttributes(mdnGlobalAttributeArray).onElements("i")

            .allowElements("img")
            .allowAttributes(imgAttributeArray).onElements("img")

            .allowElements("input")
            .allowAttributes(inputAttributeArray).onElements("input")

            .allowElements("ins")
            .allowAttributes(insAttributeArray).onElements("ins")

            .allowElements("kbd")
            .allowAttributes(mdnGlobalAttributeArray).onElements("kbd")

            .allowElements("keygen")
            .allowAttributes(keygenAttributeArray).onElements("keygen")

            .allowElements("label")
            .allowAttributes(labelAttributeArray).onElements("label")

            .allowElements("legend")
            .allowAttributes(mdnGlobalAttributeArray).onElements("legend")

            .allowElements("li")
            .allowAttributes(liAttributeArray).onElements("li")

            .allowElements("map")
            .allowAttributes(mapAttributeArray).onElements("map")

            .allowElements("mark")
            .allowAttributes(mdnGlobalAttributeArray).onElements("mark")

            .allowElements("marquee")
            .allowAttributes(marqueeDefaultAttributeArray).onElements("marquee")
            .disallowAttributes("style").onElements("marquee")

            .allowElements("menu")
            .allowAttributes(menuAttributeArray).onElements("menu")

            .allowElements("meter")
            .allowAttributes(meterAttributeArray).onElements("meter")

            .allowElements("nav")
            .allowAttributes(mdnGlobalAttributeArray).onElements("nav")

            .allowElements("nobr")

            .allowElements("noframes")
            .allowAttributes(mdnGlobalAttributeArray).onElements("noframes")

            .allowElements("noscript")
            .allowAttributes(mdnGlobalAttributeArray).onElements("noscript")

            .allowElements("ol")
            .allowAttributes(olAttributeArray).onElements("ol")

            .allowElements("optgroup")
            .allowAttributes(optgroupAttributeArray).onElements("optgroup")

            .allowElements("option")
            .allowAttributes(optionAttributeArray).onElements("option")

            .allowElements("output")
            .allowAttributes(outputAttributeArray).onElements("output")

            .allowElements("p")
            .allowAttributes(mdnGlobalAttributeArray).onElements("p")

            .allowElements("param")
            .allowAttributes(paramAttributeArray).onElements("param")

            .allowElements("pre")
            .allowAttributes(preAttributeArray).onElements("pre")

            .allowElements("progress")
            .allowAttributes(progressAttributeArray).onElements("progress")

            .allowElements("q")
            .allowAttributes(qAttributeArray).onElements("q")

            .allowElements("rp")
            .allowAttributes(mdnGlobalAttributeArray).onElements("rp")

            .allowElements("rt")
            .allowAttributes(mdnGlobalAttributeArray).onElements("rt")

            .allowElements("ruby")
            .allowAttributes(mdnGlobalAttributeArray).onElements("ruby")

            .allowElements("s")
            .allowAttributes(mdnGlobalAttributeArray).onElements("s")

            .allowElements("samp")
            .allowAttributes(mdnGlobalAttributeArray).onElements("samp")

            .allowElements("section")
            .allowAttributes(mdnGlobalAttributeArray).onElements("section")

            .allowElements("select")
            .allowAttributes(selectAttributeArray).onElements("select")

            .allowElements("small")
            .allowAttributes(mdnGlobalAttributeArray).onElements("small")

            .allowElements("source")
            .allowAttributes(sourceAttributeArray).onElements("source")

            .allowElements("span")
            .allowAttributes(mdnGlobalAttributeArray).onElements("span")

            .allowElements("strike")
            .allowAttributes(mdnGlobalAttributeArray).onElements("strike")

            .allowElements("strong")
            .allowAttributes(mdnGlobalAttributeArray).onElements("strong")

            .allowElements("sub")
            .allowAttributes(mdnGlobalAttributeArray).onElements("sub")

            .allowElements("summary")
            .allowAttributes(mdnGlobalAttributeArray).onElements("summary")

            .allowElements("sup")
            .allowAttributes(mdnGlobalAttributeArray).onElements("sup")

            .allowElements("table")
            .allowAttributes(tableAttributeArray).onElements("table")

            .allowElements("tbody")
            .allowAttributes(tbodyAttributeArray).onElements("tbody")

            .allowElements("td")
            .allowAttributes(tdAttributeArray).onElements("td")

            .allowElements("textarea")
            .allowAttributes(textareaAttributeArray).onElements("textarea")

            .allowElements("tfoot")
            .allowAttributes(tfootAttributeArray).onElements("tfoot")

            .allowElements("th")
            .allowAttributes(thAttributeArray).onElements("th")

            .allowElements("thead")
            .allowAttributes(theadAttributeArray).onElements("thead")

            .allowElements("time")
            .allowAttributes(timeAttributeArray).onElements("time")

            .allowElements("title")
            .allowAttributes(mdnGlobalAttributeArray).onElements("title")

            .allowElements("tr")
            .allowAttributes(trAttributeArray).onElements("tr")

            .allowElements("track")
            .allowAttributes(trackAttributeArray).onElements("track")

            .allowElements("tt")
            .allowAttributes(mdnGlobalAttributeArray).onElements("tt")

            .allowElements("u")
            .allowAttributes(mdnGlobalAttributeArray).onElements("u")

            .allowElements("ul")
            .allowAttributes(ulAttributeArray).onElements("ul")

            .allowElements("var")
            .allowAttributes(mdnGlobalAttributeArray).onElements("var")

            .allowElements("video")
            .allowAttributes(videoAttributeArray).onElements("video")

            .allowElements("wbr")
            .allowAttributes(mdnGlobalAttributeArray).onElements("wbr")

            .allowElements("xmp")
            .allowAttributes(mdnGlobalAttributeArray).onElements("xmp")

            .allowStyling(CssSchema.DEFAULT)
            .allowUrlsInStyles(AttributePolicy.IDENTITY_ATTRIBUTE_POLICY)
            .allowUrlProtocols("https", "http")
            .allowWithoutAttributes("a", "font", "img", "input", "span")
            .toFactory();
  }

  public static void main(String[] args) {
  }

  private static String[] appendGlobalAttributes(String[] defaultAttributeArray) {
    String[] tempArr = new String[defaultAttributeArray.length + mdnGlobalAttributeArray.length];
    System.arraycopy(defaultAttributeArray, 0, tempArr, 0, defaultAttributeArray.length);
    System.arraycopy(mdnGlobalAttributeArray, 0, tempArr, defaultAttributeArray.length, mdnGlobalAttributeArray.length);
    return tempArr;
  }
}