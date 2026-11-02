// SYNTHETIC TEST FIXTURE — not functional
// Shaped like the direction helpers of a vendored charting bundle.
const isRtl = () => "rtl" === document.dir, strip = new RegExp("‎|‪|‫|‬", "g");
function mark(e){return "" !== e && isRtl() && null != e ? "‎" + e : e}
function embedLtr(e){return "‪" + e + "‬"}
function embedRtl(e){return "‫" + e + "‬"}
function embedBoth(e){return isRtl() && null != e ? "‫" + e + "‬" : e}
