// --- Form Submission & Result Display Logic (Still Needed for LLM Tab) ---
document.addEventListener('DOMContentLoaded', () => {
    // IMPORTANT: Check if the form exists on the *currently loaded page*
    const promptForm = document.getElementById('promptForm');
    if (promptForm) {
        // Only add listener if the form is present
        const promptInput = document.getElementById('promptInput');
        const maxRetriesInput = document.getElementById('maxRetriesInput');
        const submitBtn = document.getElementById('submitBtn');
        const statusDiv = document.getElementById('status');
        const resultsDiv = document.getElementById('results');

        promptForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const prompt = promptInput ? promptInput.value.trim() : '';
            const maxRetriesValue = maxRetriesInput ? maxRetriesInput.value : '3';
            const maxRetries = parseInt(maxRetriesValue, 10);

            if (!prompt) { showStatus('Please enter a task description.', 'error', statusDiv); return; }
            if (isNaN(maxRetries) || maxRetries < 0 || maxRetries > 10) { showStatus('Max Retries must be a number between 0 and 10.', 'error', statusDiv); return; }
            if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Executing...'; }
            showStatus('Processing... Contacting LLM and executing commands...', 'loading', statusDiv);
            if(resultsDiv) resultsDiv.innerHTML = '';

            try {
                const response = await fetch('/execute', { method: 'POST', headers: { 'Content-Type': 'application/json', }, body: JSON.stringify({ prompt: prompt, max_retries: maxRetries }) });
                if(statusDiv) statusDiv.style.display = 'none';
                if (!response.ok) {
                    let errorMsg = `Error: ${response.status} ${response.statusText}`;
                    try { const errorData = await response.json(); errorMsg = `Error: ${errorData.error || response.statusText} ${errorData.message ? '- ' + errorData.message : ''}`; } catch (e) { /* Ignore */ }
                    throw new Error(errorMsg);
                }
                const data = await response.json();
                // Pass the specific divs to helper functions
                displayResults(data, resultsDiv);
                showStatus(data.overall_success ? 'Task completed successfully.' : 'Task finished, but errors occurred (see details below).', data.overall_success ? 'success' : 'error', statusDiv);
            } catch (error) {
                console.error('Fetch Error:', error);
                showStatus(`Error: ${error.message || 'Failed to process request.'}`, 'error', statusDiv);
                if (resultsDiv) { resultsDiv.innerHTML = `<p><strong>An application error occurred:</strong> ${escapeHtml(error.message)}</p>`; }
            } finally {
                 if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Execute Task'; }
            }
        });
    } // End if(promptForm)

    // --- Bootstrap Modal Initialization (Add this part!) ---
    // If you have modals triggered by data attributes, Bootstrap usually handles this automatically
    // IF the Bootstrap JS is loaded. If you need to manually initialize:
    const taskHistoryModalElement = document.getElementById('taskHistoryModal');
    if (taskHistoryModalElement) {
        // Check if Bootstrap's Modal object exists (means BS JS loaded)
        if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
             // You don't strictly *need* to create an instance here if using data attributes,
             // but it's good practice if you ever want to control the modal via JS (e.g., myModal.show())
             // const taskHistoryModal = new bootstrap.Modal(taskHistoryModalElement);
             console.log("Bootstrap Modal component found and initialized (or ready).");
        } else {
            console.error("Bootstrap JavaScript not loaded or Modal component missing!");
            // Optionally display an error to the user that modal functionality may be broken
        }
    }

}); // End DOMContentLoaded

// --- Helper Functions (Remain the same) ---
function showStatus(message, type = 'info', statusDivElement) { if(statusDivElement) { statusDivElement.textContent = message; statusDivElement.className = ''; statusDivElement.classList.add(`status-${type}`); statusDivElement.style.display = 'block'; } else { console.warn("Status div element not provided or not found."); } }
function displayResults(data, resultsDivElement) { if(!resultsDivElement) { console.warn("Results div element not provided or not found."); return; } resultsDivElement.innerHTML = ''; if (!data || !data.results || data.results.length === 0) { resultsDivElement.innerHTML = '<p>No execution attempts recorded.</p>'; return; } const overallStatusText = data.overall_success ? '<h2 style="color: #28a745;">Overall Status: Success</h2>' : '<h2 style="color: #dc3545;">Overall Status: Failed</h2>'; resultsDivElement.innerHTML += overallStatusText; data.results.forEach((attempt) => { const attemptDiv = document.createElement('div'); attemptDiv.className = 'attempt'; let content = `<h3>Attempt ${escapeHtml(attempt.attempt || '?')}</h3>`; content += `<p><strong>Prompt Sent:</strong></p><pre>${escapeHtml(attempt.prompt_sent || 'N/A')}</pre>`; let commandsHtml = '<ul>'; if (attempt.llm_commands && Array.isArray(attempt.llm_commands) && attempt.llm_commands.length > 0) { attempt.llm_commands.forEach(cmd => { commandsHtml += `<li><code>${escapeHtml(cmd)}</code></li>`; }); } else { commandsHtml += '<li>(No commands proposed)</li>'; } commandsHtml += '</ul>'; content += `<p><strong>LLM Commands Proposed:</strong></p>${commandsHtml}`; content += `<p><strong>Execution Success:</strong> <span style="font-weight: bold; color: ${attempt.execution_success ? '#28a745' : '#dc3545'};">${escapeHtml(String(attempt.execution_success))}</span></p>`; if (attempt.stdout && String(attempt.stdout).trim()) { content += `<p><strong>Output (stdout):</strong></p><pre>${escapeHtml(attempt.stdout)}</pre>`; } else { content += `<p><strong>Output (stdout):</strong> <pre>(empty)</pre></p>`; } if (attempt.stderr && String(attempt.stderr).trim()) { content += `<p><strong>Error Output (stderr):</strong></p><pre class="stderr">${escapeHtml(attempt.stderr)}</pre>`; } else { content += `<p><strong>Error Output (stderr):</strong> <pre>(empty)</pre></p>`; } attemptDiv.innerHTML = content; resultsDivElement.appendChild(attemptDiv); }); }
function escapeHtml(unsafe) { const str = String(unsafe === null || unsafe === undefined ? "" : unsafe); return str.replace(/&/g, "&").replace(/</g, "<").replace(/>/g, ">").replace(/"/g, "\"").replace(/'/g, "'"); }