document.addEventListener('DOMContentLoaded', function () {
    function applicationBackUrl(path) {
        if (path === '/profile' || path === '/upcoming-events' || path === '/events' || path === '/old-events' || path === '/calendar' || path === '/feedback' || path === '/about') {
            return '/user-home';
        }
        if (path === '/admin/profile' || path === '/admin/add-event' || path === '/admin/delete-event' || path === '/admin/calendar' || path === '/admin/feedback' || path === '/admin/about') {
            return '/admin';
        }
        if (path.startsWith('/register_event/')) {
            return path.replace('/register_event/', '/event/');
        }
        if (path.startsWith('/event/')) {
            return '/upcoming-events';
        }
        return '/';
    }

    document.querySelectorAll('[data-back]').forEach(function (button) {
        button.addEventListener('click', function () {
            window.location.href = applicationBackUrl(window.location.pathname);
        });
    });
});