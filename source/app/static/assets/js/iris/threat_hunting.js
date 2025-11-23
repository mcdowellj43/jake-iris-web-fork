// Threat Hunting Dashboard JavaScript
// IRIS Source Code - Copyright (C) 2025 - DFIR-IRIS

// Global variables
let allQueries = {};
let currentCategoryFilter = '';
let currentSeverityFilter = '';
let selectedQueryId = null;
let currentResultId = null;

// Initialize dashboard on page load
$(document).ready(function() {
    console.log('Threat Hunting Dashboard initializing...');
    loadQueryCategories();
    loadStats();
    loadExecutionHistory();

    // Auto-refresh stats every 30 seconds
    setInterval(loadStats, 30000);
});

/**
 * Load query categories and populate query list
 */
function loadQueryCategories() {
    get_raw_request_api('/threat-hunting/api/queries/categories')
        .done(function(data) {
            if (notify_auto_api(data, true)) {
                allQueries = data.data;
                populateQueryList();
            }
        });
}

/**
 * Populate the query list based on current filters
 */
function populateQueryList() {
    let queryListHtml = '';
    let queryCount = 0;

    for (let category in allQueries) {
        // Apply category filter
        if (currentCategoryFilter && category !== currentCategoryFilter) {
            continue;
        }

        // Category header
        queryListHtml += `
            <div class="mt-3 mb-2">
                <h6 class="text-primary">
                    <i class="fas fa-folder mr-2"></i>${category}
                    <span class="badge badge-light ml-2">${allQueries[category].queries.length}</span>
                </h6>
            </div>
        `;

        // Queries in this category
        for (let query of allQueries[category].queries) {
            // Apply severity filter
            if (currentSeverityFilter && query.severity !== currentSeverityFilter) {
                continue;
            }

            let severityClass = query.severity || 'medium';
            let mitreHtml = '';
            if (query.mitre_attack && query.mitre_attack.length > 0) {
                mitreHtml = query.mitre_attack.map(t =>
                    `<span class="mitre-badge">${t}</span>`
                ).join('');
            }

            queryListHtml += `
                <div class="query-item" data-query-id="${query.query_id}" onclick="selectQuery('${query.query_id}')">
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <strong>${sanitizeHTML(query.query_name)}</strong>
                            <div class="text-muted small mt-1">${sanitizeHTML(query.description)}</div>
                            <div class="mt-2">
                                <span class="query-severity ${severityClass}">${severityClass}</span>
                                ${mitreHtml}
                            </div>
                        </div>
                    </div>
                </div>
            `;
            queryCount++;
        }
    }

    if (queryCount === 0) {
        queryListHtml = '<div class="text-center text-muted py-3">No queries match your filters</div>';
    }

    $('#query-list').html(queryListHtml);
    $('#query-count').text(`${queryCount} queries`);
}

/**
 * Filter queries by category
 */
function filterByCategory() {
    currentCategoryFilter = $('#category-filter').val();
    populateQueryList();
}

/**
 * Filter queries by severity
 */
function filterBySeverity() {
    currentSeverityFilter = $('#severity-filter').val();
    populateQueryList();
}

/**
 * Select a query for execution
 */
function selectQuery(queryId) {
    selectedQueryId = queryId;

    // Update UI to show selected
    $('.query-item').removeClass('active');
    $(`.query-item[data-query-id="${queryId}"]`).addClass('active');

    // Load query details
    get_raw_request_api(`/threat-hunting/api/queries/${queryId}`)
        .done(function(data) {
            if (notify_auto_api(data, true)) {
                displayQueryDetails(data.data);
            }
        });
}

/**
 * Display query details in execution panel
 */
function displayQueryDetails(query) {
    $('#query-details-container').hide();
    $('#query-execution-form').show();

    $('#selected-query-name').text(query.query_name);
    $('#selected-query-description').text(query.description);

    let severityClass = query.severity || 'medium';
    $('#selected-query-severity')
        .removeClass()
        .addClass(`query-severity ${severityClass}`)
        .text(severityClass);

    // Display MITRE ATT&CK techniques
    let mitreHtml = '';
    if (query.mitre_attack && query.mitre_attack.length > 0) {
        mitreHtml = query.mitre_attack.map(t =>
            `<span class="mitre-badge">${t}</span>`
        ).join(' ');
    } else {
        mitreHtml = '<span class="text-muted">None specified</span>';
    }
    $('#selected-query-mitre').html(mitreHtml);

    // Set default time range if specified
    if (query.time_range) {
        $('#time-range').val(query.time_range);
    }
}

/**
 * Execute the selected query
 */
function executeQuery() {
    if (!selectedQueryId) {
        notify_error('Please select a query first');
        return;
    }

    let timeRange = $('#time-range').val();
    let indexPattern = $('#index-pattern').val();
    let caseId = $('#case-association').val();

    let payload = {
        query_id: selectedQueryId,
        time_range: timeRange,
        csrf_token: $('#csrf_token').val()
    };

    if (indexPattern) {
        payload.index_pattern = indexPattern;
    }

    if (caseId) {
        payload.case_id = parseInt(caseId);
    }

    // Show loading state
    showExecutionStatus('info', '<span class="loading-spinner"></span> Executing query...', true);

    post_request_api('/threat-hunting/api/execute', JSON.stringify(payload), true)
        .done(function(data) {
            if (data.status === 'success') {
                currentResultId = data.data.result_id;
                showExecutionStatus('success',
                    `<i class="fas fa-check-circle mr-2"></i>Query completed! Found ${data.data.hit_count} hits in ${data.data.execution_time_ms}ms`,
                    true
                );
                displayResults(data.data);
                loadExecutionHistory();
                loadStats();
            } else {
                showExecutionStatus('danger',
                    `<i class="fas fa-times-circle mr-2"></i>${data.message}`,
                    true
                );
            }
        })
        .fail(function(xhr) {
            showExecutionStatus('danger',
                `<i class="fas fa-times-circle mr-2"></i>Query execution failed: ${xhr.responseJSON?.message || 'Unknown error'}`,
                true
            );
        });
}

/**
 * Show execution status message
 */
function showExecutionStatus(type, message, show) {
    if (show) {
        $('#execution-status').show();
        $('#execution-message').html(message);
        $('#execution-status .alert')
            .removeClass('alert-info alert-success alert-danger alert-warning')
            .addClass(`alert-${type}`);
    } else {
        $('#execution-status').hide();
    }
}

/**
 * Display query results
 */
function displayResults(data) {
    let resultsHtml = '';

    // Summary section
    resultsHtml += `
        <div class="mb-3">
            <h5>${sanitizeHTML(data.query_name)}</h5>
            <div class="alert alert-info">
                <strong>Hits Found:</strong> ${data.hit_count}<br>
                <strong>Execution Time:</strong> ${data.execution_time_ms}ms
            </div>
        </div>
    `;

    // Aggregations (if available)
    if (data.aggregations && Object.keys(data.aggregations).length > 0) {
        resultsHtml += `
            <div class="mb-3">
                <h6><i class="fas fa-chart-pie mr-2"></i>Aggregated Results</h6>
                <div class="card bg-light">
                    <div class="card-body">
                        ${formatAggregations(data.aggregations)}
                    </div>
                </div>
            </div>
        `;
    }

    // Results table
    if (data.results && data.results.length > 0) {
        resultsHtml += `
            <div class="mb-3">
                <h6><i class="fas fa-list mr-2"></i>Sample Events (First ${Math.min(data.results.length, 100)})</h6>
                <div class="results-container">
                    <div class="results-timeline">
        `;

        for (let i = 0; i < Math.min(data.results.length, 20); i++) {
            let result = data.results[i];
            let source = result._source || {};
            let timestamp = source['@timestamp'] || 'Unknown';
            let eventCode = source.event?.code || 'N/A';
            let hostName = source.host?.name || 'Unknown';

            resultsHtml += `
                <div class="timeline-item">
                    <small class="text-muted">${timestamp}</small>
                    <div><strong>Host:</strong> ${sanitizeHTML(hostName)}</div>
                    <div><strong>Event Code:</strong> ${eventCode}</div>
                    <button class="btn btn-sm btn-link p-0" onclick="showEventDetails(${i})">
                        <i class="fas fa-eye mr-1"></i>View Details
                    </button>
                </div>
            `;
        }

        resultsHtml += `
                    </div>
                </div>
            </div>
        `;
    } else if (data.hit_count === 0) {
        resultsHtml += `
            <div class="alert alert-success">
                <i class="fas fa-check-circle mr-2"></i>
                No threats detected! This is good news.
            </div>
        `;
    }

    $('#results-container').html(resultsHtml);
    $('#results-actions').show();

    // Store results globally for detail viewing
    window.currentResults = data.results;
}

/**
 * Format aggregation results for display
 */
function formatAggregations(aggregations) {
    let html = '';

    for (let aggName in aggregations) {
        let agg = aggregations[aggName];

        if (agg.buckets) {
            html += `<div class="mb-2"><strong>${aggName}:</strong></div>`;
            html += '<ul class="list-unstyled ml-3">';

            for (let bucket of agg.buckets.slice(0, 10)) {
                let key = bucket.key_as_string || bucket.key;
                let count = bucket.doc_count;
                html += `<li>${sanitizeHTML(String(key))}: <span class="badge badge-primary">${count}</span></li>`;
            }

            if (agg.buckets.length > 10) {
                html += `<li class="text-muted">...and ${agg.buckets.length - 10} more</li>`;
            }

            html += '</ul>';
        } else if (agg.value !== undefined) {
            html += `<div><strong>${aggName}:</strong> ${agg.value}</div>`;
        }
    }

    return html || '<em>No aggregations available</em>';
}

/**
 * Show detailed event information in modal
 */
function showEventDetails(index) {
    if (!window.currentResults || !window.currentResults[index]) {
        notify_error('Event details not available');
        return;
    }

    let event = window.currentResults[index];
    let source = event._source || {};

    // Create modal content
    let modalHtml = `
        <div class="modal fade" id="eventDetailsModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Event Details</h5>
                        <button type="button" class="close" data-dismiss="modal">
                            <span>&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <pre><code>${JSON.stringify(source, null, 2)}</code></pre>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Remove existing modal if present
    $('#eventDetailsModal').remove();

    // Add and show modal
    $('body').append(modalHtml);
    $('#eventDetailsModal').modal('show');
}

/**
 * Load execution history
 */
function loadExecutionHistory() {
    get_raw_request_api('/threat-hunting/api/results/history?limit=10')
        .done(function(data) {
            if (notify_auto_api(data, true)) {
                displayExecutionHistory(data.data);
            }
        });
}

/**
 * Display execution history
 */
function displayExecutionHistory(history) {
    if (!history || history.length === 0) {
        $('#execution-history').html('<div class="text-muted text-center">No recent executions</div>');
        return;
    }

    let historyHtml = '<div class="list-group">';

    for (let item of history) {
        let statusClass = item.status === 'completed' ? 'success' : 'danger';
        let timestamp = new Date(item.created_at).toLocaleString();

        historyHtml += `
            <div class="list-group-item list-group-item-action" onclick="loadHistoricalResult('${item.result_id}')">
                <div class="d-flex justify-content-between">
                    <strong class="text-truncate">${sanitizeHTML(item.query_name)}</strong>
                    <span class="exec-status ${item.status}">${item.status}</span>
                </div>
                <small class="text-muted">
                    ${timestamp} | ${item.hit_count} hits | ${item.execution_time_ms}ms
                </small>
            </div>
        `;
    }

    historyHtml += '</div>';
    $('#execution-history').html(historyHtml);
}

/**
 * Load a historical result
 */
function loadHistoricalResult(resultId) {
    get_raw_request_api(`/threat-hunting/api/results/${resultId}`)
        .done(function(data) {
            if (notify_auto_api(data, true)) {
                currentResultId = resultId;
                displayResults({
                    query_name: data.data.query_name,
                    hit_count: data.data.hit_count,
                    execution_time_ms: data.data.execution_time_ms,
                    results: data.data.results,
                    aggregations: data.data.aggregations
                });
                $('#results-actions').show();
            }
        });
}

/**
 * Load dashboard statistics
 */
function loadStats() {
    get_raw_request_api('/threat-hunting/api/stats')
        .done(function(data) {
            if (notify_auto_api(data, true)) {
                let stats = data.data;
                $('#stat-total-executions').text(stats.total_executions || 0);
                $('#stat-executions-24h').text(stats.executions_24h || 0);
                $('#stat-total-hits').text(stats.total_hits || 0);
            }
        });
}

/**
 * Test OpenSearch connection
 */
function testOpenSearchConnection() {
    post_request_api('/threat-hunting/api/test-connection', JSON.stringify({
        csrf_token: $('#csrf_token').val()
    }), true)
        .done(function(data) {
            if (data.status === 'success') {
                let result = data.data;
                notify_success(`Connected successfully to ${result.cluster_name} (v${result.version}) - Response time: ${result.response_time_ms}ms`);
            } else {
                notify_error(data.message);
            }
        });
}

/**
 * Add results to case
 */
function addResultsToCase() {
    if (!currentResultId) {
        notify_error('No results available to add');
        return;
    }

    // Pre-fill case ID if one was specified during execution
    let caseId = $('#case-association').val();
    if (caseId) {
        $('#modal-case-id').val(caseId);
    }

    $('#addToCaseModal').modal('show');
}

/**
 * Confirm adding results to case
 */
function confirmAddToCase() {
    let caseId = $('#modal-case-id').val();

    if (!caseId) {
        notify_error('Please enter a case ID');
        return;
    }

    if (!currentResultId) {
        notify_error('No results available');
        return;
    }

    let payload = {
        case_id: parseInt(caseId),
        csrf_token: $('#csrf_token').val()
    };

    post_request_api(
        `/threat-hunting/api/results/${currentResultId}/add-to-case?cid=${caseId}`,
        JSON.stringify(payload),
        true
    )
        .done(function(data) {
            if (data.status === 'success') {
                $('#addToCaseModal').modal('hide');
                notify_success(`Results added to case ${data.data.case_id} as note ${data.data.note_id}`);
            } else {
                notify_error(data.message);
            }
        });
}
