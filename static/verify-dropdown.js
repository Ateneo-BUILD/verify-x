/**
 * Reusable searchable dropdown autocomplete widget.
 *
 * Usage:
 *   var dd = VerifyDropdown.create({
 *       searchId: 'my-search-input',
 *       hiddenId: 'my-hidden-input',
 *       dropdownId: 'my-dropdown-div',
 *       onSelect: function(item) { ... },
 *       onInput: function() { ... }
 *   });
 *   dd.setItems([{id: 1, name: 'Foo'}, ...]);
 */
var VerifyDropdown = (function() {
    'use strict';

    function create(opts) {
        var allItems = [];
        var searchEl = document.getElementById(opts.searchId);
        var hiddenEl = document.getElementById(opts.hiddenId);
        var dropdownEl = document.getElementById(opts.dropdownId);

        function setItems(items) { allItems = items; }

        function render(filter) {
            var q = (filter || '').toLowerCase();
            var matches = allItems.filter(function(item) {
                return item.name.toLowerCase().indexOf(q) >= 0;
            });
            dropdownEl.innerHTML = '';
            matches.forEach(function(item) {
                var div = document.createElement('div');
                div.textContent = item.name;
                div.style.cssText = 'padding:0.5rem 0.75rem; cursor:pointer; font-size:0.9rem;';
                div.addEventListener('mouseenter', function() { this.style.background = '#e8eef3'; });
                div.addEventListener('mouseleave', function() { this.style.background = ''; });
                div.addEventListener('mousedown', function(e) {
                    e.preventDefault();
                    searchEl.value = item.name;
                    hiddenEl.value = item.id;
                    dropdownEl.style.display = 'none';
                    if (opts.onSelect) opts.onSelect(item);
                });
                dropdownEl.appendChild(div);
            });
            if (matches.length === 0) {
                var empty = document.createElement('div');
                empty.textContent = 'No items found';
                empty.style.cssText = 'padding:0.5rem 0.75rem; color:#999; font-size:0.85rem;';
                dropdownEl.appendChild(empty);
            }
            dropdownEl.style.display = (matches.length > 0 || q) ? 'block' : 'none';
        }

        searchEl.addEventListener('focus', function() { render(this.value); });
        searchEl.addEventListener('input', function() {
            hiddenEl.value = '';
            if (opts.onInput) opts.onInput();
            render(this.value);
        });
        searchEl.addEventListener('blur', function() {
            setTimeout(function() { dropdownEl.style.display = 'none'; }, 150);
        });

        return { setItems: setItems };
    }

    return { create: create };
})();
