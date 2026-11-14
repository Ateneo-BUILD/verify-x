/**
 * Shared liveness overlay helpers — used by app.html and login.html.
 */
var VerifyLiveness = (function() {
    'use strict';

    function showOverlay(message) {
        var el = document.getElementById('liveness-overlay');
        var text = document.getElementById('liveness-overlay-text');
        if (text) text.textContent = message;
        if (el) el.style.display = 'flex';
    }

    function hideOverlay() {
        var el = document.getElementById('liveness-overlay');
        if (el) el.style.display = 'none';
        var cover = document.getElementById('sdk-spinner-cover');
        if (cover) cover.remove();
    }

    function releaseCamera() {
        if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
            try {
                document.querySelectorAll('video').forEach(function(v) {
                    var stream = v.srcObject;
                    if (stream) {
                        stream.getTracks().forEach(function(t) { t.stop(); });
                        v.srcObject = null;
                    }
                });
            } catch(e) { /* ignore */ }
        }
        document.querySelectorAll('iframe[src*="everify"], iframe[src*="liveness"]').forEach(function(el) {
            el.remove();
        });
    }

    return {
        showOverlay: showOverlay,
        hideOverlay: hideOverlay,
        releaseCamera: releaseCamera
    };
})();
