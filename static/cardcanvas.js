/* The verification card, drawn into a canvas.

   ONE renderer, two media. This file is what `/card/<token>/` draws on the
   holder's phone AND what the document prints below its cut line, turned on
   its side: one design for one object, so somebody holding the paper and
   the photo side by side sees the same card.

   So the card has one description and it is here. A change made for the
   phone changes what prints, which is the point of the file and also its
   risk: `DocumentCredentialTest` is what has to catch a phone-side change
   that ruins the paper.

   It draws and nothing else. No saving, no platform sniffing, no page
   chrome -- those differ between the two consumers and stay with them.

   Everything below is lifted out of `card.html` unmodified apart from the
   canvas arriving as a parameter instead of being looked up by id. */
window.CardCanvas = (function () {
    'use strict';

    /* card:    the payload the server built -- see handoff.payload_from_rows
       canvas:  1080 x 2700, and the caller owns it
       sealSrc: the authentication mark, same-origin so the canvas stays
                untainted and toBlob() can run

       Resolves with the canvas once everything that has to be on it is. */
    function render(card, canvas, sealSrc) {
        /* ---- the design grid ------------------------------------------------
           Every number is in a 1080 px grid and the canvas IS that grid, so the
           exported PNG is 1080 x 2700 whatever phone drew it. Fixed rather than
           taken from devicePixelRatio: the image gets shared onward, and a card
           whose size depended on which handset made it is a card nobody can
           reason about.

           The symbol size is not a preference. STAMP_MM 48.8 over MIN_MODULE_MM
           0.4 allows at most 121 modules -- QR version 26 -- for either symbol on
           any document at any field count, so 121 x 8 px is what both boxes are
           sized for and nothing shrinks when an organization switches fields on.

           Full width, deliberately. Fit-to-screen on a portrait image is bound by
           HEIGHT, so trimming a symbol to make the card shorter shrinks the card
           by less than it shrinks the symbol: measured, 60% symbols take an
           iPhone 15 from 0.459 mm per module down to 0.331. Let the card be
           tall. */
        var W = 1080, H = 2700, M = 56;
        var MAX_MODULES = 121;      // version 26; see above
        var MODULE_PX = 8;
        var SYM = MAX_MODULES * MODULE_PX;                 // 968

        var BANDS = [
            ['topMargin', 48], ['header', 140], ['rule', 24], ['identity', 150],
            ['gap1', 28], ['cap1', 34], ['gap2', 12], ['sym1', SYM],
            ['gap3', 32], ['cap2', 34], ['gap4', 12], ['sym2', SYM],
            ['gap5', 32], ['meta', 120], ['rule2', 16], ['uuid', 34],
            ['bottomMargin', 48]
        ];

        var INK = '#16202b', BLUE = '#00529b', DEEP = '#00386a',
            MUTED = '#7c8b99', LINE = '#e6ecf2';
        var FACE = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
        var MONO = "'SFMono-Regular', Menlo, Consolas, 'Liberation Mono', monospace";

            var ctx = canvas.getContext('2d');

        /* ---- text ------------------------------------------------------------
           Shrink, then wrap, then clip -- in that order, and the holder's name is
           the reason. The document trims the organization, the transaction type
           and the location and never the name; this does the same, by giving the
           name more lines to use before anything is lost. */
        function font(size, weight, family) {
            return (weight || 400) + ' ' + size + 'px ' + (family || FACE);
        }

        function wrap(text, size, weight, family, maxWidth) {
            ctx.font = font(size, weight, family);
            var words = String(text || '').split(/\s+/).filter(Boolean);
            var lines = [], line = '';
            for (var i = 0; i < words.length; i++) {
                var next = line ? line + ' ' + words[i] : words[i];
                if (line && ctx.measureText(next).width > maxWidth) {
                    lines.push(line);
                    line = words[i];
                } else {
                    line = next;
                }
            }
            if (line) { lines.push(line); }
            return lines;
        }

        function clip(text, size, weight, family, maxWidth) {
            ctx.font = font(size, weight, family);
            var value = String(text || '');
            if (ctx.measureText(value).width <= maxWidth) { return value; }
            while (value.length > 1
                   && ctx.measureText(value + '…').width > maxWidth) {
                value = value.slice(0, -1);
            }
            return value + '…';
        }

        /* One string on one line, shrunk to fit and clipped only if even the
           floor will not hold it. */
        function line(text, x, y, opts) {
            var size = opts.size;
            while (size > opts.min && (ctx.font = font(size, opts.weight, opts.family),
                   ctx.measureText(String(text || '')).width > opts.width)) {
                size -= 1;
            }
            ctx.font = font(size, opts.weight, opts.family);
            ctx.fillStyle = opts.color || INK;
            ctx.textBaseline = opts.baseline || 'top';
            ctx.fillText(clip(text, size, opts.weight, opts.family, opts.width), x, y);
            return size;
        }

        /* A block that may take several lines, shrinking until it fits the
           allowance. */
        function block(text, x, y, opts) {
            var size = opts.size, lines;
            for (;;) {
                lines = wrap(text, size, opts.weight, opts.family, opts.width);
                if (lines.length <= opts.maxLines || size <= opts.min) { break; }
                size -= 2;
            }
            lines = lines.slice(0, opts.maxLines);
            ctx.font = font(size, opts.weight, opts.family);
            ctx.fillStyle = opts.color || INK;
            ctx.textBaseline = 'top';
            var lh = Math.round(size * (opts.lineHeight || 1.15));
            for (var i = 0; i < lines.length; i++) {
                var text_ = (i === lines.length - 1)
                    ? clip(lines[i], size, opts.weight, opts.family, opts.width)
                    : lines[i];
                ctx.fillText(text_, x, y + i * lh);
            }
            return lines.length * lh;
        }

        /* ---- the symbols -----------------------------------------------------
           qrcode-generator defaults addData to BYTE mode -- `mode = mode ||
           'Byte'` in the library -- and nothing about an uppercase payload
           changes that. Byte mode costs about 45% of the capacity, which on the
           document put the portrait past what any QR can hold and drew the
           credential far above the version its stamp was sized for. Ask for the
           mode; never assume it. Same rule, same test, as document.html. */
        var ALNUM = /^[0-9A-Z $%*+\-.\/:]*$/;

        /* ---- one box, whatever the version ------------------------------
           An integer module means a symbol measures `cells x unit`, so two
           symbols of different versions are different SIZES: a 113-module
           credential draws 904 px inside the same 968 box a 121-module portrait
           fills exactly. Side by side that reads as a mistake -- and the
           document's printed card has never had it, because there each symbol is
           scaled into a fixed 48.8 mm box whatever its version.

           So the BOX is drawn. Both symbols then occupy the same square whatever
           the ink inside measures, and nothing about the ink changes: the module
           stays an integer 8 px, which is the property this function exists to
           protect.

           The frame is LIGHT, and that is what makes it safe against a symbol
           that fills its box exactly. A quiet zone has to be free of DARK marks;
           #dfe6ec is 88% luminance, so a binariser reads it as background, the
           same way it reads the paper. A dark rule here would have had to sit 4
           modules out, which costs the card 128 px of height. */
        function drawSymbol(payload, x, y, box) {
            var qr = qrcode(0, 'Q');
            qr.addData(payload, ALNUM.test(payload) ? 'Alphanumeric' : 'Byte');
            qr.make();
            var cells = qr.getModuleCount();
            // An INTEGER module, or every edge lands mid-pixel and the whole
            // symbol softens. Whatever is left over becomes quiet zone.
            var unit = Math.max(1, Math.floor(box / cells));
            var size = unit * cells;
            var ox = x + Math.round((box - size) / 2);
            var oy = y + Math.round((box - size) / 2);
            ctx.fillStyle = '#fff';
            ctx.fillRect(x, y, box, box);
            ctx.strokeStyle = '#dfe6ec';
            ctx.lineWidth = 2;
            ctx.strokeRect(x + 1, y + 1, box - 2, box - 2);
            ctx.fillStyle = INK;
            for (var r = 0; r < cells; r++) {
                for (var c = 0; c < cells; c++) {
                    if (qr.isDark(r, c)) {
                        ctx.fillRect(ox + c * unit, oy + r * unit, unit, unit);
                    }
                }
            }
        }

        function caption(text, y) {
            ctx.font = font(24, 600, MONO);
            ctx.fillStyle = MUTED;
            ctx.textBaseline = 'top';
            var label = String(text).toUpperCase();
            // Letter-spacing by hand: canvas has no such property in the browsers
            // this has to run on.
            var x = M;
            for (var i = 0; i < label.length; i++) {
                ctx.fillText(label[i], x, y);
                x += ctx.measureText(label[i]).width + 3;
            }
            ctx.strokeStyle = LINE;
            ctx.lineWidth = 2;
            ctx.beginPath();
            ctx.moveTo(x + 12, y + 13);
            ctx.lineTo(W - M, y + 13);
            ctx.stroke();
        }

        /* Aspect fit, never crop: the upstream portrait is already framed on the
           face, and squaring it off is how you cut somebody's chin off. */
        function drawFace(image, x, y, box) {
            ctx.fillStyle = '#eef2f6';
            ctx.fillRect(x, y, box, box);
            if (image && image.naturalWidth) {
                var scale = Math.min(box / image.naturalWidth,
                                     box / image.naturalHeight);
                var w = image.naturalWidth * scale, h = image.naturalHeight * scale;
                ctx.drawImage(image, x + (box - w) / 2, y + (box - h) / 2, w, h);
            }
            ctx.strokeStyle = '#dfe6ec';
            ctx.lineWidth = 2;
            ctx.strokeRect(x + 1, y + 1, box - 2, box - 2);
        }

        function draw(seal, face) {
            var y = 0, inner = W - 2 * M;
            function band(name) {
                for (var i = 0; i < BANDS.length; i++) {
                    if (BANDS[i][0] === name) { return BANDS[i][1]; }
                }
                return 0;
            }
            function advance(name) { var top = y; y += band(name); return top; }

            ctx.fillStyle = '#fff';
            ctx.fillRect(0, 0, W, H);

            advance('topMargin');

            // --- header: the seal, and what this document is -----------------
            var top = advance('header');
            var sealBox = 132;
            if (seal && seal.naturalWidth) {
                var s = Math.min(sealBox / seal.naturalWidth,
                                 sealBox / seal.naturalHeight);
                ctx.drawImage(seal, M, top + (sealBox - seal.naturalHeight * s) / 2,
                              seal.naturalWidth * s, seal.naturalHeight * s);
            }
            var hx = M + sealBox + 24, hw = W - M - hx;
            if (card.expires_on) {
                /* The date in the header, read early and costing the card
                   nothing.
                   It takes the title's second line, so the title is held to one:
                   30 px fits it in any font this has to run on. */
                line('National ID Authentication Result', hx, top + 8,
                     {size: 40, weight: 800, width: hw, min: 30, color: DEEP});
                line(card.organization, hx, top + 56,
                     {size: 28, weight: 400, width: hw, min: 20, color: '#5d6d7c'});
                ctx.font = font(32, 400);
                var lead = ctx.measureText('Expires ').width;
                line('Expires ', hx, top + 96,
                     {size: 32, weight: 400, width: hw, min: 32, color: '#5d6d7c'});
                line(card.expires_on, hx + lead, top + 96,
                     {size: 32, weight: 800, width: hw - lead, min: 24, color: DEEP});
            } else {
                block('National ID Authentication Result', hx, top + 8,
                      {size: 40, weight: 800, width: hw, maxLines: 2, min: 30,
                       color: DEEP, lineHeight: 1.15});
                line(card.organization, hx, top + 104,
                     {size: 28, weight: 400, width: hw, min: 20, color: '#5d6d7c'});
            }

            // --- the rule ----------------------------------------------------
            top = advance('rule');
            ctx.fillStyle = BLUE;
            ctx.fillRect(M, top + 8, inner, 5);

            /* --- who it is ---------------------------------------------------
               Above the symbols, and that is a decision rather than an oversight.
               The image is two and a half screens tall, so what sits at the top
               is what the camera roll shows as a thumbnail -- and a grid of QR
               thumbnails is unfindable a week later. Everything below this band
               is still symbols first. */
            top = advance('identity');
            var faceBox = 132;
            drawFace(face, M, top, faceBox);
            var ix = M + faceBox + 24, iw = W - M - ix;
            var used = block(card.holder || '—', ix, top,
                             {size: 52, weight: 800, width: iw, maxLines: 2,
                              min: 34, lineHeight: 1.1});
            var ids = [card.card_number, card.digital_id]
                .filter(Boolean).join('  ·  ');
            line(ids, ix, top + used + 12,
                 {size: 30, weight: 400, family: MONO, width: iw, min: 20,
                  color: '#5d6d7c'});

            // --- the two symbols, stacked ------------------------------------
            advance('gap1');
            caption('Credential', advance('cap1'));
            advance('gap2');
            drawSymbol(card.qr, M, advance('sym1'), SYM);

            advance('gap3');
            if (card.portrait_qr) {
                caption('Portrait', advance('cap2'));
                advance('gap4');
                drawSymbol(card.portrait_qr, M, advance('sym2'), SYM);
            } else {
                // No portrait symbol on this verification. The band is left
                // blank rather than the layout resized: one card geometry is
                // what makes the sizing above true of every card.
                advance('cap2'); advance('gap4'); advance('sym2');
            }
            advance('gap5');

            // --- the three context strings -----------------------------------
            top = advance('meta');
            var rows = [['Transaction', card.transaction_type],
                        ['Location', card.location],
                        ['Verified', card.verified_at]];
            for (var i = 0; i < rows.length; i++) {
                var ry = top + i * 40;
                line(rows[i][0], M, ry + 4,
                     {size: 26, weight: 600, width: 300, min: 20, color: MUTED});
                line(rows[i][1] || '—', M + 320, ry,
                     {size: 30, weight: 400, width: W - M - (M + 320), min: 20});
            }

            // --- the transaction id, in full ---------------------------------
            top = advance('rule2');
            ctx.fillStyle = LINE;
            ctx.fillRect(M, top + 8, inner, 2);
            top = advance('uuid');
            line(card.transaction_id, M, top,
                 {size: 24, weight: 400, family: MONO, width: inner, min: 16,
                  color: '#93a1ae'});
        }

        /* ---- load what has to be on the canvas, then draw ------------------- */
        function load(src) {
            return new Promise(function (resolve) {
                if (!src) { return resolve(null); }
                var img = new Image();
                // Resolve either way: a card without a face is still a card, and
                // a card that never appears because one image 404ed is not.
                img.onload = function () { resolve(img); };
                img.onerror = function () { resolve(null); };
                img.src = src;
            });
        }

        return Promise.all([load(sealSrc), load(card.face)])
            .then(function (images) {
                draw(images[0], images[1]);
                return canvas;
            });
    }

    return { render: render };
})();
