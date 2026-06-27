const API="http://localhost:8000";

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


    document.getElementById("explanation")
    .innerText=data.details.explanation;


    let redFlags=document.getElementById("redFlags");

    redFlags.innerHTML="";

    if(data.details.red_flags){

        data.details.red_flags.forEach(flag=>{

            redFlags.innerHTML+=
            `<li>${flag}</li>`;
        });
    }

    let score=1-data.risk_score;

    new Chart(
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