
// Select all list items that trigger highlighting
const triggers = document.querySelectorAll('.highlight-trigger');

// Loop through each trigger
triggers.forEach(trigger => {
    // Add hover event listeners
    trigger.addEventListener('mouseenter', () => {
        const targetId = trigger.getAttribute('data-target');
        const targetElement = document.querySelector(`#${targetId}`);
        targetElement.classList.add('highlighted');
    });

    trigger.addEventListener('mouseleave', () => {
        const targetId = trigger.getAttribute('data-target');
        const targetElement = document.querySelector(`#${targetId}`);
        targetElement.classList.remove('highlighted');
    });
});
