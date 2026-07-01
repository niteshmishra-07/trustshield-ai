const API="http://localhost:8000";

async function loadHistory(){

    let response=
    await fetch(API+"/history");

    let data=await response.json();

    let table=document.getElementById("historyTable");

    // Build the header + every row as an array of strings and join +
    // assign innerHTML ONCE at the end. The previous version did
    // `table.innerHTML += rowHtml` inside the loop, which forces the
    // browser to re-parse and re-render the *entire* accumulated table
    // on every single iteration -- O(n^2) work for n rows. On a history
    // page with any real amount of data that's the difference between
    // an instant render and a multi-second freeze.
    let rows = [`
    <tr>
        <th>Type</th>
        <th>Verdict</th>
        <th>Trust Score</th>
        <th>Category</th>
        <th>Risk</th>
        <th>Date</th>
    </tr>`];

    data.analyses.forEach(item=>{

        rows.push(`
        <tr>
            <td>${item.input_type}</td>
            <td>${item.verdict}</td>
            <td>${item.details?.trust_score ?? "N/A"}</td>
            <td>${item.details?.category ?? "Unknown"}</td>
            <td>${item.risk_score}</td>
            <td>${new Date(item.analyzed_at)
            .toLocaleString()}</td>
        </tr>`);
    });

    table.innerHTML = rows.join("");

}

loadHistory();