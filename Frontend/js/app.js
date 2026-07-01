const API="http://localhost:8000";

// Holds the single live Chart.js instance bound to #scoreChart.
// Without this, showResult() created a brand-new Chart on the same
// <canvas> every time an analysis finished, and Chart.js never garbage
// collects the old ones on its own -- each leftover instance keeps its
// own animation/render loop running. After a handful of analyses the
// page visibly slows down and the canvas gets janky. Track the instance
// and destroy() it before creating the next one.
let scoreChartInstance = null;

function scrollToAnalyzer(){
    document
    .getElementById("analyzer")
    .scrollIntoView({behavior:"smooth"});
}

function showTab(tab){

    document.querySelectorAll(".tab-content")
    .forEach(x=>x.classList.remove("active"));

    document.querySelectorAll(".tab")
    .forEach(x=>x.classList.remove("active"));

    document
    .getElementById(tab+"Tab")
    .classList.add("active");

    event.target.classList.add("active");
}


async function analyzeText(){

    let text=document.getElementById("textInput").value;

    let response=await fetch(API+"/analyze/text",{

        method:"POST",

        headers:{
            "Content-Type":"application/json"
        },

        body:JSON.stringify({text})
    });

    let data=await response.json();

    showResult(data);
}


async function analyzeURL(){

    let url=document.getElementById("urlInput").value;

    let response=await fetch(API+"/analyze/url",{

        method:"POST",

        headers:{
            "Content-Type":"application/json"
        },

        body:JSON.stringify({url})
    });

    let data=await response.json();

    showResult(data);
}


async function analyzeImage(){

    let file=
    document.getElementById("imageInput").files[0];

    let formData=new FormData();

    formData.append("file",file);

    let response=await fetch(API+"/analyze/image",{

        method:"POST",
        body:formData
    });

    let data=await response.json();

    showResult(data);
}



function showResult(data){

    document
    .getElementById("resultSection")
    .classList.remove("hidden");


    document.getElementById("verdict")
    .innerText=data.verdict.toUpperCase();


    document.getElementById("trustScore")
    .innerText = "Trust Score: " + (data.details.trust_score ?? "N/A") + " / 100";


    document.getElementById("scamCategory")
    .innerText = data.details.category ?? "Unknown";


    document.getElementById("explanation")
    .innerText=data.details.explanation;

    let redFlags=document.getElementById("redFlags");

    // Build the full list as one string and set innerHTML once, instead
    // of using `innerHTML +=` inside the loop (each += re-parses and
    // re-renders everything accumulated so far -- O(n^2) for n flags).
    if(data.details.red_flags && data.details.red_flags.length){
        redFlags.innerHTML = data.details.red_flags
            .map(flag=>`<li>${flag}</li>`)
            .join("");
    } else {
        redFlags.innerHTML="";
    }

    let score=1-data.risk_score;

    // Destroy the previous chart instance before creating a new one --
    // see the `scoreChartInstance` comment near the top of this file.
    if(scoreChartInstance){
        scoreChartInstance.destroy();
    }

    scoreChartInstance = new Chart(
        document.getElementById("scoreChart"),
        {
            type:'doughnut',

            data:{
                datasets:[{
                    data:[score*100,100-score*100]
                }]
            }
        }
    );
}