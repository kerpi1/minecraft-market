// static/js/main.js

// Функция для конвертации UTC времени в локальное
function convertToLocalTime() {
    const timeElements = document.querySelectorAll('.local-time');
    timeElements.forEach(element => {
        const utcTime = element.getAttribute('data-utc-time');
        if (utcTime) {
            try {
                const date = new Date(utcTime);
                if (isNaN(date.getTime())) {
                    console.warn('Некорректная дата UTC:', utcTime);
                    return;
                }
                const localTime = date.toLocaleString('ru-RU', {
                    day: '2-digit',
                    month: '2-digit',
                    year: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                    timeZoneName: 'short'
                });
                element.textContent = localTime;
            } catch (e) {
                console.error('Ошибка при конвертации времени:', e);
            }
        }
    });
}

// Выполняем конвертацию при загрузке страницы
document.addEventListener('DOMContentLoaded', convertToLocalTime);
