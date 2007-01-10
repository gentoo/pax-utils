<?xml version="1.0"?>
<xsl:stylesheet  
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:import
  href="http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl" />

  <xsl:template match="itemizedlist/listitem">
    <xsl:text>&#x2022;&#10;</xsl:text>
    <xsl:apply-templates/>
    <xsl:if test="following-sibling::listitem">
      <xsl:text>.sp -1&#10;</xsl:text>
      <xsl:text>.TP</xsl:text>
      <xsl:if test="not($list-indent = '')">
        <xsl:text> </xsl:text>
        <xsl:value-of select="$list-indent"/>
      </xsl:if>
      <xsl:text>&#10;</xsl:text>
    </xsl:if>
  </xsl:template>
</xsl:stylesheet>
