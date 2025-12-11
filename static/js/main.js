let lastScrollTop = 0;
    const header = document.querySelector("header");

    window.addEventListener("scroll", function() {
      const currentScroll = window.pageYOffset || document.documentElement.scrollTop;

      if (currentScroll > lastScrollTop && currentScroll > 100) {
        header.style.transform = "translateY(-100%)";
      } else {
        header.style.transform = "translateY(0)";
        header.style.boxShadow = currentScroll > 0 ? "0 2px 6px rgba(0,0,0,0.1)" : "none";
      }

      lastScrollTop = currentScroll <= 0 ? 0 : currentScroll;
    }, false);


document.querySelectorAll('.flash-message').forEach((el, i) => {
          setTimeout(() => {
            el.classList.remove('scale-95', 'opacity-0');
            el.classList.add('scale-100', 'opacity-100');
          }, 100 * i);
          setTimeout(() => {
            el.style.transition = 'opacity 0.5s ease';
            el.style.opacity = '0';
            setTimeout(() => el.remove(), 500);
          }, 3000 + i * 200);
        });


// ✅ السماح بالزر الأيمن مجدداً
      // (نحذف أو نعلّق السطر اللي يمنعه)
      // document.addEventListener('contextmenu', e => e.preventDefault());

      // ⚙️ منع بعض الاختصارات فقط (Ctrl+S / Ctrl+U / PrintScreen)
      document.addEventListener('keydown', e => {
        if (e.ctrlKey && ['s','S','u','U'].includes(e.key)) e.preventDefault();
        if (e.key === 'PrintScreen') {
          try { navigator.clipboard.writeText(''); } catch(e){}
        }
      });

      // ✨ أنيميشن البطاقات كما كانت
      window.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('.card').forEach((c, i) =>
          setTimeout(() => c.classList.add('show'), i * 100)
        );
      });


// ✅ السماح بالزر الأيمن مجدداً
      document.addEventListener('keydown', e => {
        if (e.ctrlKey && ['s','S','u','U'].includes(e.key)) e.preventDefault();
        if (e.key === 'PrintScreen') {
          try { navigator.clipboard.writeText(''); } catch(e){}
        }
      });

      window.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('.card').forEach((c, i) =>
          setTimeout(() => c.classList.add('show'), i * 100)
        );
      });
