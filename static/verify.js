/**
 * Shared verify utilities — QR scanning, result display, button helpers.
 */
var Verify = (function() {
    'use strict';

    // ---- Result display ----

    function showResult(el, success, message) {
        el.className = 'result-box ' + (success ? 'success' : 'error');
        el.textContent = message;
        el.style.display = 'block';
    }

    function hideResult(el) {
        el.style.display = 'none';
    }

    // ---- Button state helper ----

    function withButtonState(btn, loadingText, asyncFn) {
        var original = btn.textContent;
        btn.disabled = true;
        btn.textContent = loadingText;
        return asyncFn().finally(function() {
            btn.disabled = false;
            btn.textContent = original;
        });
    }

    // ---- QR Camera Scanner ----

    function QRScanner(opts) {
        this.video = document.getElementById(opts.videoId);
        this.canvas = document.getElementById(opts.canvasId);
        this.container = document.getElementById(opts.containerId);
        this.onDetected = opts.onDetected || function() {};
        this._stream = null;
        this._interval = null;
    }

    QRScanner.prototype.start = function() {
        var self = this;
        return navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
            .then(function(stream) {
                self._stream = stream;
                self.video.srcObject = stream;
                self.video.play();
                self.container.style.display = 'block';
                self._interval = setInterval(function() { self._scanFrame(); }, 300);
            });
    };

    QRScanner.prototype.stop = function() {
        if (this._interval) { clearInterval(this._interval); this._interval = null; }
        if (this._stream) {
            this._stream.getTracks().forEach(function(t) { t.stop(); });
            this._stream = null;
        }
        this.video.srcObject = null;
        this.container.style.display = 'none';
    };

    QRScanner.prototype._scanFrame = function() {
        if (!this.video.videoWidth) return;
        var ctx = this.canvas.getContext('2d');
        this.canvas.width = this.video.videoWidth;
        this.canvas.height = this.video.videoHeight;
        ctx.drawImage(this.video, 0, 0);
        var imageData = ctx.getImageData(0, 0, this.canvas.width, this.canvas.height);
        var code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code && code.data) {
            this.onDetected(code.data);
        }
    };

    // ---- QR from image file (client-side via jsQR) ----

    function decodeQRFromFile(file, canvas, callback) {
        var reader = new FileReader();
        reader.onload = function(e) {
            var img = new Image();
            img.onload = function() {
                var ctx = canvas.getContext('2d');
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);
                var imageData = ctx.getImageData(0, 0, img.width, img.height);
                var code = jsQR(imageData.data, imageData.width, imageData.height);
                callback(code ? code.data : null);
            };
            img.src = e.target.result;
        };
        reader.readAsDataURL(file);
    }

    // ---- ID extraction from QR data ----

    function extractIdFromQR(data) {
        var s = data.trim();
        // Match Digital National ID: 3 letters + 3-4 digits (e.g. ABC1234)
        var digitalMatch = s.match(/^([A-Za-z]{3}\d{3,4})$/);
        if (digitalMatch) return digitalMatch[1];
        // Strip dashes/spaces, match 16-digit National ID Card Number
        var stripped = s.replace(/[-\s]/g, '');
        if (/^\d{16}$/.test(stripped)) return stripped;
        return null;
    }

    // ---- ID masking on screen (shoulder-surfing, not Demo Mode) ----

    // The echo convention is mask_identifier's: a bullet run of
    // deliberately wrong length with the last character kept, so a scan
    // can be confirmed on screen without the confirmation undoing the
    // masked field beside it.
    function maskId(value) {
        var s = String(value || '').toUpperCase();
        if (!s) return s;
        return '•••••' + s.charAt(s.length - 1);
    }

    // A National ID input is masked by the platform (type="password");
    // Show ID flips the input's own type, so there is no styling that
    // could quietly fail to apply and leave the ID readable.
    function idMaskToggle(input, button) {
        button.addEventListener('click', function() {
            var reveal = input.type === 'password';
            input.type = reveal ? 'text' : 'password';
            button.textContent = reveal ? 'Hide ID' : 'Show ID';
            button.setAttribute('aria-pressed', reveal ? 'true' : 'false');
            input.focus();
        });
    }

    // ---- Liveness camera zoom hint ----

    // PSA's liveness capture draws a fixed 640x480 CSS-px camera box. When
    // the browser's scale (display scaling x browser zoom) puts that box on
    // a fractional number of device pixels, its white mask leaves the
    // video's outermost pixel ring uncovered: a 1-px line of camera image
    // around the box. Measured on real zoom levels -- no page-side fix
    // exists, because the frame is drawn at the browser's own scale -- so
    // the operator is told the one thing that helps. 160 is the common
    // factor of 640 and 480; both are whole iff 160 x dpr is. The tolerance
    // absorbs float noise (1.95 arrives as 1.9499999...), not real zoom.
    var LIVENESS_BOX_UNIT_PX = 160;

    function livenessZoomDrawsLines() {
        var units = LIVENESS_BOX_UNIT_PX * (window.devicePixelRatio || 1);
        return Math.abs(units - Math.round(units)) > 0.01;
    }

    function livenessZoomHint(el) {
        if (!el) return;
        function update() { el.hidden = !livenessZoomDrawsLines(); }
        update();
        // Zooming the page fires resize, so the hint follows Ctrl+/-/0 live.
        window.addEventListener('resize', update);
    }

    return {
        showResult: showResult,
        hideResult: hideResult,
        withButtonState: withButtonState,
        QRScanner: QRScanner,
        decodeQRFromFile: decodeQRFromFile,
        extractIdFromQR: extractIdFromQR,
        maskId: maskId,
        idMaskToggle: idMaskToggle,
        livenessZoomDrawsLines: livenessZoomDrawsLines,
        livenessZoomHint: livenessZoomHint
    };
})();
