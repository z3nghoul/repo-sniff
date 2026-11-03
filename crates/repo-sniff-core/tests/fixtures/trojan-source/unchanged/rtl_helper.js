// SYNTHETIC TEST FIXTURE — not functional
// Shaped like the direction helpers of a vendored charting bundle.
const isRtl = () => "rtl" === document.dir, strip = new RegExp("{{LRM}}|{{LRE}}|{{RLE}}|{{PDF}}", "g");
function mark(e){return "" !== e && isRtl() && null != e ? "{{LRM}}" + e : e}
function embedLtr(e){return "{{LRE}}" + e + "{{PDF}}"}
function embedRtl(e){return "{{RLE}}" + e + "{{PDF}}"}
function embedBoth(e){return isRtl() && null != e ? "{{RLE}}" + e + "{{PDF}}" : e}
