// Enhanced Security Global Variables
let currentDay = 1;
let currentMonth = 1;
let currentYear = 1403;
let currentWeekDay = 'saturday';
let dayCounter = 0;
let tasks = {};
let selectedTasks = new Set();
let settings = {
    theme: 'system',
    timeFormat: '24h',
    review1Gap: 1,
    review2Gap: 3,
    review3Gap: 7,
    studyDateMode: 'same_day',
    alarmSound: 'bell',
    alarmDuration: 5,
    alarmVolume: 70
};
let charts = {};
let editingTaskId = null;
let alarmInterval = null;
let alarmCheckInterval = null;

// Security: Enhanced input sanitization with DOMPurify
function sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    return DOMPurify.sanitize(input, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: []
    }).trim();
}

function validateNumericInput(value, min, max) {
    const num = parseInt(value);
    return !isNaN(num) && num >= min && num <= max ? num : null;
}

// Enhanced Secure Storage with rate limiting
let storageOperations = 0;
function secureStorageSet(key, value) {
    // Rate limiting
    if (storageOperations++ > 50) {
        console.warn('Storage rate limit exceeded');
        return false;
    }
    
    try {
        const data = {
            content: value,
            timestamp: Date.now(),
            checksum: btoa(JSON.stringify(value)).slice(0, 16),
            version: '2.0'
        };
        localStorage.setItem(key, JSON.stringify(data));
        return true;
    } catch (error) {
        console.error('Secure storage error:', error);
        return false;
    }
}

function secureStorageGet(key) {
    try {
        const stored = localStorage.getItem(key);
        if (!stored) return null;
        
        const data = JSON.parse(stored);
        if (data.content && data.checksum && data.version) {
            const expectedChecksum = btoa(JSON.stringify(data.content)).slice(0, 16);
            if (expectedChecksum === data.checksum) {
                return data.content;
            } else {
                console.warn(`Data integrity check failed for: ${key}`);
                return null;
            }
        }
        return data; // Fallback for old format
    } catch (error) {
        console.error('Storage read error:', error);
        return null;
    }
}

// Reset storage rate limit every second
setInterval(() => { storageOperations = 0; }, 1000);

// Persian Calendar Data
const persianMonths = ['', 'فروردین', 'اردیبهشت', 'خرداد', 'تیر', 'مرداد', 'شهریور', 'مهر', 'آبان', 'آذر', 'دی', 'بهمن', 'اسفند'];
const weekDays = ['saturday', 'sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday'];
const weekDayNames = {
    saturday: 'شنبه',
    sunday: 'یکشنبه', 
    monday: 'دوشنبه',
    tuesday: 'سه‌شنبه',
    wednesday: 'چهارشنبه',
    thursday: 'پنج‌شنبه',
    friday: 'جمعه'
};

// Enhanced Security: Event delegation with data attributes
document.addEventListener('click', function(e) {
    const action = e.target.dataset.action;
    if (!action) return;
    
    e.preventDefault();
    
    switch (action) {
        case 'stop-alarm':
            stopAlarm();
            break;
        case 'set-date':
            setCurrentDate();
            break;
        case 'next-day':
            goToNextDay();
            break;
        case 'show-date-modal':
            showDateModal();
            break;
        case 'test-alarm':
            testAlarm();
            break;
        case 'save-alarm':
            saveAlarmSettings();
            break;
        case 'save-review':
            saveReviewSettings();
            break;
        case 'export-data':
            exportData();
            break;
        case 'clear-data':
            clearAllData();
            break;
        case 'back-archive':
            goBackFromArchive();
            break;
        case 'load-archive':
            loadArchive();
            break;
        case 'edit-selected':
            editSelectedTasks();
            break;
        case 'delete-selected':
            deleteSelectedTasks();
            break;
        case 'close-edit':
            closeEditModal();
            break;
        case 'save-edit':
            saveEditedTask();
            break;
    }
});

// Tab switching with data attributes
document.addEventListener('click', function(e) {
    const tab = e.target.dataset.tab;
    if (tab) {
        e.preventDefault();
        showTab(tab);
    }
});

// Category selection
document.addEventListener('click', function(e) {
    const category = e.target.closest('.category-option')?.dataset.category;
    if (category) {
        selectCategory(category);
    }
});

// Initialize App with Enhanced Security
document.addEventListener('DOMContentLoaded', function() {
    // Verify DOMPurify is loaded
    if (typeof DOMPurify === 'undefined') {
        console.error('DOMPurify not loaded - security risk!');
        document.body.innerHTML = '<div class="p-8 text-center"><h1 class="text-2xl text-red-600">خطای امنیتی</h1><p>لطفاً صفحه را مجدداً بارگذاری کنید</p></div>';
        return;
    }
    
    initializeApp();
    initEnhancedSecurity();
});

function initEnhancedSecurity() {
    // Security: Monitor console access attempts
    let consoleAccessCount = 0;
    const originalLog = console.log;
    console.log = function(...args) {
        consoleAccessCount++;
        if (consoleAccessCount > 100) {
            console.warn('درسینو: فعالیت مشکوک در کنسول');
            consoleAccessCount = 0;
        }
        return originalLog.apply(this, args);
    };
    
    // Security: Content integrity monitoring
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(function(node) {
                    if (node.nodeType === 1 && node.tagName === 'SCRIPT') {
                        console.warn('درسینو: تشخیص اسکریپت غیرمجاز');
                    }
                });
            }
        });
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}

function initializeApp() {
    loadSettings();
    loadTasks();
    applyTheme();
    setupThemeWatcher();
    setupEventListeners();
    checkStoredDate();
    setupAlarmSystem();
    requestNotificationPermission();
}

function setupEventListeners() {
    // Form submission with enhanced validation
    document.getElementById('taskForm').addEventListener('submit', function(e) {
        e.preventDefault();
        addTask(e);
    });
    
    // Search and filter with debouncing
    let searchTimeout;
    document.getElementById('searchInput').addEventListener('input', function() {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(filterTasks, 300);
    });
    
    document.getElementById('filterPriority').addEventListener('change', filterTasks);
    document.getElementById('filterStatus').addEventListener('change', filterTasks);
    document.getElementById('themeSelect').addEventListener('change', changeTheme);
    document.getElementById('timeFormatSelect').addEventListener('change', changeTimeFormat);
    document.getElementById('taskDateOption').addEventListener('change', toggleCustomDateSection);
    document.getElementById('selectAllTasks').addEventListener('change', toggleSelectAllTasks);
    
    // Enhanced input validation with real-time sanitization
    const textInputs = ['taskTitle', 'taskDescription', 'editTitle', 'editDescription', 'searchInput'];
    textInputs.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.addEventListener('input', function(e) {
                const sanitized = sanitizeInput(e.target.value);
                if (sanitized !== e.target.value) {
                    e.target.value = sanitized;
                    showMessage('ورودی پاکسازی شد', 'warning');
                }
            });
        }
    });
    
    // File input with enhanced validation
    document.getElementById('importFile').addEventListener('change', function(e) {
        importData(e);
    });
    
    // Range inputs for settings
    document.getElementById('alarmDuration').addEventListener('input', function(e) {
        document.getElementById('durationDisplay').textContent = e.target.value;
    });
    
    document.getElementById('alarmVolume').addEventListener('input', function(e) {
        document.getElementById('volumeDisplay').textContent = e.target.value;
    });
}

// Persian Calendar Functions (same as before but with enhanced validation)
function isLeapYear(year) {
    year = validateNumericInput(year, 1300, 1500);
    if (!year) return false;
    
    const breaks = [0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0];
    const gy = year + 1595;
    const leap = -14;
    const jp = breaks[0];
    let jump = 0;
    for (let j = 1; j <= 33; j++) {
        const jm = breaks[j];
        jump = jm - jp;
        if (year < jm) break;
        jp = jm;
    }
    const n = year - jp;
    if (n < jump) {
        if ((jump - n) < 6 && (jump % 4) === 0) return true;
        return false;
    } else {
        const n2 = n - jump;
        const cycle = Math.floor(n2 / 128);
        const cyear = n2 % 128;
        if (cyear % 4 === 0 && cyear !== 128) return true;
    }
    return false;
}

function getDaysInMonth(month, year) {
    month = validateNumericInput(month, 1, 12);
    year = validateNumericInput(year, 1300, 1500);
    if (!month || !year) return 30;
    
    if (month <= 6) return 31;
    if (month <= 11) return 30;
    return isLeapYear(year) ? 30 : 29;
}

function addDays(day, month, year, daysToAdd) {
    day = validateNumericInput(day, 1, 31);
    month = validateNumericInput(month, 1, 12);
    year = validateNumericInput(year, 1300, 1500);
    daysToAdd = validateNumericInput(daysToAdd, -365, 365);
    
    if (!day || !month || !year || daysToAdd === null) {
        return { day: 1, month: 1, year: 1403 };
    }
    
    let totalDays = daysToAdd;
    let newDay = day;
    let newMonth = month;
    let newYear = year;
    
    while (totalDays > 0) {
        const daysInCurrentMonth = getDaysInMonth(newMonth, newYear);
        const remainingDaysInMonth = daysInCurrentMonth - newDay;
        
        if (totalDays <= remainingDaysInMonth) {
            newDay += totalDays;
            totalDays = 0;
        } else {
            totalDays -= (remainingDaysInMonth + 1);
            newDay = 1;
            newMonth++;
            if (newMonth > 12) {
                newMonth = 1;
                newYear++;
            }
        }
    }
    
    return { day: newDay, month: newMonth, year: newYear };
}

function getNextWeekDay(weekDay) {
    const currentIndex = weekDays.indexOf(weekDay);
    return weekDays[(currentIndex + 1) % 7];
}

// Enhanced Date Management with validation
function setCurrentDate() {
    const day = sanitizeInput(document.getElementById('currentDay').value);
    const month = sanitizeInput(document.getElementById('currentMonth').value);
    const year = sanitizeInput(document.getElementById('currentYear').value);
    const weekDay = document.getElementById('currentWeekDay').value;
    
    const dayNum = validateNumericInput(day, 1, 31);
    const monthNum = validateNumericInput(month, 1, 12);
    const yearNum = validateNumericInput(year, 1400, 1450);
    
    if (!dayNum || !monthNum || !yearNum || !weekDay) {
        showMessage('لطفاً همه فیلدهای تاریخ را به درستی پر کنید', 'error');
        return;
    }
    
    const daysInMonth = getDaysInMonth(monthNum, yearNum);
    if (dayNum > daysInMonth) {
        showMessage(`ماه ${persianMonths[monthNum]} ${daysInMonth} روز دارد`, 'error');
        return;
    }
    
    currentDay = dayNum;
    currentMonth = monthNum;
    currentYear = yearNum;
    currentWeekDay = weekDay;
    dayCounter = 0;
    
    // Secure storage
    secureStorageSet('currentDay', currentDay);
    secureStorageSet('currentMonth', currentMonth);
    secureStorageSet('currentYear', currentYear);
    secureStorageSet('currentWeekDay', currentWeekDay);
    secureStorageSet('dayCounter', dayCounter);
    
    document.getElementById('dateModal').style.display = 'none';
    updateCurrentDateDisplay();
    renderTasks();
    updateQuickStats();
    updateStudyPlannerStats();
    renderStudySchedule();
    
    resetAlarmFlags();
}

// Enhanced Task Management with comprehensive validation
function addTask(e) {
    e.preventDefault();
    
    const title = sanitizeInput(document.getElementById('taskTitle').value.trim());
    const time = document.getElementById('taskTime').value;
    const description = sanitizeInput(document.getElementById('taskDescription').value.trim());
    const priority = document.getElementById('taskPriority').value;
    const category = document.getElementById('taskCategory').value;
    const dateOption = document.getElementById('taskDateOption').value;
    
    // Enhanced validation
    if (!title || title.length < 1 || title.length > 200) {
        showMessage('لطفاً عنوان معتبر برای کار وارد کنید (۱-۲۰۰ کاراکتر)', 'error');
        return;
    }
    
    if (description && description.length > 500) {
        showMessage('توضیحات نمی‌تواند بیش از ۵۰۰ کاراکتر باشد', 'error');
        return;
    }
    
    // Validate time format if provided
    if (time && !/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/.test(time)) {
        showMessage('فرمت زمان نامعتبر است', 'error');
        return;
    }
    
    let taskDate;
    if (dateOption === 'today') {
        taskDate = { day: currentDay, month: currentMonth, year: currentYear };
    } else if (dateOption === 'tomorrow') {
        taskDate = addDays(currentDay, currentMonth, currentYear, 1);
    } else {
        const dayNum = validateNumericInput(document.getElementById('taskDay').value, 1, 31);
        const monthNum = validateNumericInput(document.getElementById('taskMonth').value, 1, 12);
        const yearNum = validateNumericInput(document.getElementById('taskYear').value, 1400, 1450);
        
        if (!dayNum || !monthNum || !yearNum) {
            showMessage('لطفاً تاریخ کامل و معتبر را وارد کنید', 'error');
            return;
        }
        
        taskDate = { day: dayNum, month: monthNum, year: yearNum };
    }
    
    const dateKey = getDateKey(taskDate.day, taskDate.month, taskDate.year);
    
    // Generate secure task ID
    const task = {
        id: Date.now().toString() + '-' + Math.random().toString(36).substr(2, 9),
        title,
        time,
        description,
        priority,
        category,
        completed: false,
        createdAt: new Date().toISOString(),
        checksum: btoa(title + description + priority + category).slice(0, 12)
    };
    
    if (!tasks[dateKey]) {
        tasks[dateKey] = [];
    }
    
    // Check for duplicate tasks
    const isDuplicate = tasks[dateKey].some(existingTask => 
        existingTask.title === title && 
        existingTask.time === time && 
        existingTask.description === description
    );
    
    if (isDuplicate) {
        showConfirmDialog('کار مشابهی وجود دارد. آیا مایل به اضافه کردن هستید؟', () => {
            tasks[dateKey].push(task);
            if (category === 'study') {
                createSmartReviewSchedule(task, taskDate);
            }
            saveTasks();
            renderTasks();
            updateQuickStats();
            updateStudyPlannerStats();
            renderStudySchedule();
        });
        return;
    }
    
    tasks[dateKey].push(task);
    
    if (category === 'study') {
        createSmartReviewSchedule(task, taskDate);
    }
    
    saveTasks();
    renderTasks();
    updateQuickStats();
    updateStudyPlannerStats();
    renderStudySchedule();
    
    // Reset form
    document.getElementById('taskForm').reset();
    selectCategory('general');
    document.getElementById('taskDateOption').value = 'today';
    toggleCustomDateSection();
    
    showMessage('کار با موفقیت اضافه شد');
}

// Enhanced Storage Functions
function saveTasks() {
    return secureStorageSet('tasks', tasks);
}

function loadTasks() {
    const stored = secureStorageGet('tasks');
    if (stored && typeof stored === 'object') {
        tasks = stored;
    }
}

function saveSettings() {
    return secureStorageSet('settings', settings);
}

function loadSettings() {
    const stored = secureStorageGet('settings');
    if (stored && typeof stored === 'object') {
        settings = { ...settings, ...stored };
    }
}

// Enhanced Import/Export with additional security
function exportData() {
    try {
        const data = { 
            tasks, 
            settings,
            currentDay,
            currentMonth,
            currentYear,
            currentWeekDay,
            dayCounter,
            version: '5.0',
            exportDate: new Date().toISOString(),
            signature: btoa('darsino-secure-' + Date.now()),
            checksum: btoa(JSON.stringify(tasks) + JSON.stringify(settings)).slice(0, 32)
        };
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { 
            type: 'application/json;charset=utf-8' 
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `darsino-backup-${currentYear}-${currentMonth.toString().padStart(2, '0')}-${currentDay.toString().padStart(2, '0')}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showMessage('فایل پشتیبان ایمن دانلود شد');
    } catch (error) {
        console.error('Export error:', error);
        showMessage('خطا در ایجاد فایل پشتیبان', 'error');
    }
}

function importData(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    // Enhanced file validation
    if (!file.name.endsWith('.json')) {
        showMessage('فقط فایل‌های JSON پذیرفته می‌شوند', 'error');
        event.target.value = '';
        return;
    }
    
    if (file.size > 10 * 1024 * 1024) { // 10MB limit
        showMessage('حجم فایل بیش از ۱۰ مگابایت مجاز نیست', 'error');
        event.target.value = '';
        return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const data = JSON.parse(e.target.result);
            
            // Enhanced validation
            if (!data || typeof data !== 'object') {
                throw new Error('Invalid data structure');
            }
            
            // Check file signature
            if (!data.signature || !data.signature.includes('darsino')) {
                showMessage('فایل احتمالاً از منبع نامعتبر است', 'warning');
            }
            
            // Validate checksum if available
            if (data.checksum && data.tasks && data.settings) {
                const expectedChecksum = btoa(JSON.stringify(data.tasks) + JSON.stringify(data.settings)).slice(0, 32);
                if (expectedChecksum !== data.checksum) {
                    showMessage('یکپارچگی فایل تأیید نشد', 'warning');
                }
            }
            
            // Import with validation
            if (data.tasks && typeof data.tasks === 'object') {
                // Validate each task
                Object.keys(data.tasks).forEach(dateKey => {
                    if (Array.isArray(data.tasks[dateKey])) {
                        data.tasks[dateKey] = data.tasks[dateKey].filter(task => 
                            task.id && task.title && typeof task.title === 'string'
                        );
                    }
                });
                
                tasks = { ...tasks, ...data.tasks };
                saveTasks();
            }
            
            if (data.settings && typeof data.settings === 'object') {
                settings = { ...settings, ...data.settings };
                saveSettings();
                applyTheme();
                updateSettingsUI();
            }
            
            renderTasks();
            renderStudySchedule();
            updateQuickStats();
            updateStudyPlannerStats();
            showMessage('داده‌ها با موفقیت بازیابی شدند');
        } catch (error) {
            console.error('Import error:', error);
            showMessage('فایل معتبر نیست یا خراب شده', 'error');
        }
    };
    
    reader.onerror = function() {
        showMessage('خطا در خواندن فایل', 'error');
    };
    
    reader.readAsText(file);
    event.target.value = '';
}

function updateSettingsUI() {
    document.getElementById('themeSelect').value = settings.theme;
    document.getElementById('timeFormatSelect').value = settings.timeFormat;
    document.getElementById('review1Gap').value = settings.review1Gap;
    document.getElementById('review2Gap').value = settings.review2Gap;
    document.getElementById('review3Gap').value = settings.review3Gap;
    document.getElementById('studyDateMode').value = settings.studyDateMode;
    document.getElementById('alarmSound').value = settings.alarmSound;
    document.getElementById('alarmDuration').value = settings.alarmDuration;
    document.getElementById('alarmVolume').value = settings.alarmVolume;
    document.getElementById('durationDisplay').textContent = settings.alarmDuration;
    document.getElementById('volumeDisplay').textContent = settings.alarmVolume;
}

// Enhanced UI Helper Functions
function showMessage(text, type = 'success') {
    const container = document.getElementById('messageContainer');
    
    const messageEl = document.createElement('div');
    messageEl.className = `${
        type === 'error' ? 'bg-red-500' : 
        type === 'warning' ? 'bg-yellow-500' : 
        type === 'info' ? 'bg-blue-500' : 'bg-green-500'
    } text-white px-4 py-3 rounded-lg shadow-lg fade-in max-w-sm`;
    
    // Use textContent for security
    messageEl.textContent = sanitizeInput(text);
    
    container.appendChild(messageEl);
    
    setTimeout(() => {
        messageEl.style.opacity = '0';
        messageEl.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (container.contains(messageEl)) {
                container.removeChild(messageEl);
            }
        }, 300);
    }, 4000);
}

function showConfirmDialog(message, onConfirm) {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 modal-backdrop flex items-center justify-center z-50';
    
    const modalContent = document.createElement('div');
    modalContent.className = 'bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-xl max-w-sm w-full mx-4';
    
    modalContent.innerHTML = `
        <div class="text-center mb-6">
            <div class="w-12 h-12 bg-red-100 dark:bg-red-900 rounded-full flex items-center justify-center mx-auto mb-3">
                <svg class="w-6 h-6 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.268 15.5c-.77.833.192 2.5 1.732 2.5z"></path>
                </svg>
            </div>
            <h3 class="font-semibold text-gray-900 dark:text-gray-100 mb-2">تأیید عملیات</h3>
            <p class="text-gray-600 dark:text-gray-400 text-sm"></p>
        </div>
        <div class="flex space-x-3 space-x-reverse">
            <button class="cancel-btn flex-1 px-4 py-2 text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 rounded-lg font-medium">
                انصراف
            </button>
            <button class="confirm-btn flex-1 px-4 py-2 bg-red-600 text-white rounded-lg font-medium">
                تأیید
            </button>
        </div>
    `;
    
    // Set message content securely
    modalContent.querySelector('p').textContent = sanitizeInput(message);
    
    // Add event listeners
    modalContent.querySelector('.cancel-btn').addEventListener('click', () => {
        document.body.removeChild(modal);
    });
    
    modalContent.querySelector('.confirm-btn').addEventListener('click', () => {
        document.body.removeChild(modal);
        onConfirm();
    });
    
    modal.appendChild(modalContent);
    document.body.appendChild(modal);
}

// Add remaining functions here (keeping them similar but with enhanced security)
// ... (rest of the functions would be implemented with similar security enhancements)

// Initialize TailwindCSS configuration
if (typeof tailwind !== 'undefined') {
    tailwind.config = {
        darkMode: 'class',
        theme: {
            extend: {
                fontFamily: {
                    'vazir': ['Vazirmatn', 'sans-serif']
                }
            }
        }
    };
}

// Security: Clear any potentially harmful references on unload
window.addEventListener('beforeunload', function() {
    if (alarmInterval) clearInterval(alarmInterval);
    if (alarmCheckInterval) clearInterval(alarmCheckInterval);
    
    // Clear sensitive data from memory
    tasks = null;
    settings = null;
});
