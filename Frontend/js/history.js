const API="http://localhost:8000";

async function loadHistory(){

    let response=
    await fetch(API+"/history");

    let data=await response.json();

    let table=document.getElementById("historyTable");

    table.innerHTML=`
    <tr>
        <th>Type</th>
        <th>Verdict</th>
        <th>Risk</th>
        <th>Date</th>
    </tr>`;

    data.analyses.forEach(item=>{

        table.innerHTML+=`
        <tr>
            <td>${item.input_type}</td>
            <td>${item.verdict}</td>
            <td>${item.risk_score}</td>
            <td>${new Date(item.analyzed_at)
            .toLocaleString()}</td>
        </tr>`;
    });

}

loadHistory();