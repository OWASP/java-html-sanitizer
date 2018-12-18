package org.owasp.html.antisamy;

import org.owasp.html.antisamy.Tag;

import java.net.URL;
import java.util.Map;

/**
 * Contains a bunch of optimized lookups over the regular Policy Class. For internal use only.
 *
 * Not part of any public api and may explode or self destruct at any given moment, preferably both.
 *
 * @author Kristian Rosenvold
 */
public class InternalPolicy extends Policy {
    private final int maxInputSize;
    private final boolean isNofollowAnchors;
    private final boolean isValidateParamAsEmbed;
    private final boolean formatOutput;
    private final boolean preserveSpace;
    private final boolean omitXmlDeclaration;
    private final boolean omitDoctypeDeclaration;
    private final boolean entityEncodeIntlCharacters;
    private final boolean useXhtml;
    private final Tag embedTag;
    private final Tag styleTag;
    private final String onUnknownTag;
    private final boolean preserveComments;
    private final boolean embedStyleSheets;
    private final boolean isEncodeUnknownTag;
    private final boolean allowDynamicAttributes;


    protected InternalPolicy(URL baseUrl, ParseContext parseContext) throws PolicyException {
        super(parseContext);
        this.maxInputSize = determineMaxInputSize();
        this.isNofollowAnchors = isTrue(Policy.ANCHORS_NOFOLLOW);
        this.isValidateParamAsEmbed = isTrue(Policy.VALIDATE_PARAM_AS_EMBED);
        this.formatOutput = isTrue(Policy.FORMAT_OUTPUT);
        this.preserveSpace = isTrue(Policy.PRESERVE_SPACE);
        this.omitXmlDeclaration = isTrue(Policy.OMIT_XML_DECLARATION);
        this.omitDoctypeDeclaration = isTrue(Policy.OMIT_DOCTYPE_DECLARATION);
        this.entityEncodeIntlCharacters = isTrue(Policy.ENTITY_ENCODE_INTL_CHARS);
        useXhtml = isTrue(Policy.USE_XHTML);
        embedTag = getTagByLowercaseName("embed");
        this.onUnknownTag = getDirective("onUnknownTag");
        this.isEncodeUnknownTag = "encode".equals(onUnknownTag);
        this.preserveComments = isTrue(Policy.PRESERVE_COMMENTS);
        this.styleTag = getTagByLowercaseName("style");
        this.embedStyleSheets = isTrue(Policy.EMBED_STYLESHEETS);
        this.allowDynamicAttributes = isTrue(Policy.ALLOW_DYNAMIC_ATTRIBUTES);
    }

    protected InternalPolicy(Policy old, Map<String, String> directives, Map<String, Tag> tagRules) {
        super(old, directives, tagRules);
        this.maxInputSize = determineMaxInputSize();
        this.isNofollowAnchors = isTrue(Policy.ANCHORS_NOFOLLOW);
        this.isValidateParamAsEmbed = isTrue(Policy.VALIDATE_PARAM_AS_EMBED);
        this.formatOutput = isTrue(Policy.FORMAT_OUTPUT);
        this.preserveSpace = isTrue(Policy.PRESERVE_SPACE);
        this.omitXmlDeclaration = isTrue(Policy.OMIT_XML_DECLARATION);
        this.omitDoctypeDeclaration = isTrue(Policy.OMIT_DOCTYPE_DECLARATION);
        this.entityEncodeIntlCharacters = isTrue(Policy.ENTITY_ENCODE_INTL_CHARS);
        useXhtml = isTrue(Policy.USE_XHTML);
        embedTag = getTagByLowercaseName("embed");
        this.onUnknownTag = getDirective("onUnknownTag");
        this.isEncodeUnknownTag = "encode".equals(onUnknownTag);
        this.preserveComments = isTrue(Policy.PRESERVE_COMMENTS);
        this.styleTag = getTagByLowercaseName("style");
        this.embedStyleSheets = isTrue(Policy.EMBED_STYLESHEETS);
        this.allowDynamicAttributes = isTrue(Policy.ALLOW_DYNAMIC_ATTRIBUTES);
    }

    public Tag getEmbedTag() {
        return embedTag;
    }

    public Tag getStyleTag() {
        return styleTag;
    }

    public boolean isEmbedStyleSheets() {
        return embedStyleSheets;
    }

    public boolean isPreserveComments() {
        return preserveComments;
    }

    public int getMaxInputSize() {
        return maxInputSize;
    }

    public boolean isEntityEncodeIntlCharacters() {
        return entityEncodeIntlCharacters;
    }

    public boolean isNofollowAnchors() {
        return isNofollowAnchors;
    }

    public boolean isValidateParamAsEmbed() {
        return isValidateParamAsEmbed;
    }

    public boolean isFormatOutput() {
        return formatOutput;
    }

    public boolean isPreserveSpace() {
        return preserveSpace;
    }

    public boolean isOmitXmlDeclaration() {
        return omitXmlDeclaration;
    }

    public boolean isUseXhtml() {
        return useXhtml;
    }

    public boolean isOmitDoctypeDeclaration() {
        return omitDoctypeDeclaration;
    }

    private boolean isTrue(String anchorsNofollow) {
        return "true".equals(getDirective(anchorsNofollow));
    }


    public String getOnUnknownTag() {
        return onUnknownTag;
    }

    public boolean isEncodeUnknownTag() {
        return isEncodeUnknownTag;
    }

    public boolean isAllowDynamicAttributes() {
        return allowDynamicAttributes;
    }

    /**
     * Returns the maximum input size. If this value is not specified by
     * the policy, the <code>DEFAULT_MAX_INPUT_SIZE</code> is used.
     *
     * @return the maximium input size.
     */
    public int determineMaxInputSize() {
        int maxInputSize = Policy.DEFAULT_MAX_INPUT_SIZE;

        try {
            maxInputSize = Integer.parseInt(getDirective("maxInputSize"));
        } catch (NumberFormatException ignore) {
        }

        return maxInputSize;
    }
}
