const socket = io();

socket.on('new_anomaly', function(data) {
    const list = document.getElementById('anomalyList');
    const item = document.createElement('li');
    item.textContent = `[${data.timestamp}] ${data.api} - Error Rate: ${data.error_rate} (Env: ${data.env})`;
    list.prepend(item); // Add new item at the top
});
