var checksList
var checkStatuses = {}
var severity = "warning"

// format an incoming result, deal with counters and related administration
function handleIncomingResult(data) {
	data = JSON.parse(data);
	check_name = data.check.toLowerCase();

	// add to result table
	$("#table_"+check_name).append(formatResult(data));

	// update counters
	checkStatuses["admin"][levelToName(data.level)] += 1;
	updateCheckStatus("admin");
	checkStatuses[check_name][levelToName(data.level)] += 1;
	updateCheckStatus(check_name);

	// check if one or all checks are finished
	if( data.mnemonic == "FINISH" ) {
		finishCheck(check_name);
		if( check_name == "admin" ) {
			$("#startbutton").html(`Start checks`);
			$("#startbutton").prop("disabled", false);
		}
	}
}

// initialization
$.when( $.ready ).then(function() {
	// show current software version, because why not?
	$.ajax({
		url: '/api/version',
		success: function(data) {
			$("#version").text(data.params);
		},
	});

	// retreieve list of potential checks
	$.ajax({
		url: '/api/control/checks',
		success: function(data) {
			checksList = data.params;
			showChecksList()
		},
	});

	// prepare receiving results via WebSocket
	webSocket = new WebSocket("http://localhost:8080/api/results/")
	webSocket.onmessage = (event) => {
		handleIncomingResult(event.data);
	};

	// handler for severity filter changes
	$("#severity_filter").on('change', function() {
		severity = $(this).val();
		switch(severity) {
		case "all":
			$(".result_level_detail").show();
			$(".result_level_info").show();
			$(".result_level_warning").show();
			break;
		case "info":
			$(".result_level_detail").hide();
			$(".result_level_info").show();
			$(".result_level_warning").show();
			break;
		case "warning":
			$(".result_level_detail").hide();
			$(".result_level_info").hide();
			$(".result_level_warning").show();
			break;
		default:
			$(".result_level_detail").hide();
			$(".result_level_info").hide();
			$(".result_level_warning").hide();
		}
	});

	// handler for start button click
	$("#startbutton").on("click", startChecks)
});

// show the list of available checks together with checkboxes
function showChecksList() {
	$("#checkslist").empty();
	if (checksList.length === 0) {
		$("#checkslist").append(`
<div class="row">
	<div class="col">No checks available</div>
</div>`);
	} else {
		checksList.forEach(function(check) {
			$("#checks_list_table").append(`
<div class="row">
	<div class="col-sm-2">
	  <input class="form-check-input" type="checkbox" id="check_run_`+check+`" checked>
	</div>
	<div class="col-sm-10">
 	 <label class="form-check-label" for="check_run_`+check+`">`+check+`</label>
	</div>
</div>`);
		});
	}
}

// start the selected checks upon clicking the start button
function startChecks() {
	// reset state
	checkStatuses = {}
	$("#results_accordion").empty();

	container = $("#results_accordion")
	container.append(createCheckAccordionItem("admin"));
	checkStatuses["admin"] = newCheckStatus();
	updateCheckStatus("admin");

	// collect the list of checks to run
	var checksToDo = []
	items = $("input[type='checkbox']").filter(':checked')
	for (const [key, value] of Object.entries(items)) {
		if( value.id!=null && value.id.startsWith("check_run_")) {
			check_name = value.id.slice("check_run_".length)
			checksToDo.push(check_name);
			container.append(createCheckAccordionItem(check_name));
			checkStatuses[check_name] = newCheckStatus();
			updateCheckStatus(check_name);
		}
	}

	// get the party started
	$.ajax({
		url: "/api/control/start",
		type: "POST",
		headers: {"Content-Type": "application/json"},
		data: JSON.stringify({
			checks: checksToDo,
			ipv4: $("#af4").is(":checked"),
			ipv6: $("#af6").is(":checked"),
		}),
	});

	// prevent double-clicking the button
	$("#startbutton").html(`<span>Running...</span> <span class="spinner-border spinner-border-sm"></span>`);
	$("#startbutton").prop("disabled", true);
}

// create an accordion item for a check with the given name
function createCheckAccordionItem(check_name) {
return `
<div class="accordion-item">
	<h2 class="accordion-header">
		<button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#results_accordion_`+check_name+`">
			<div class="container-fluid">
				<div class="row">
					<div class="col-sm-5">`+check_name+`</div>
					<div class="col-sm-6"><div class="ms-auto" id="check_status_`+check_name+`"></div></div>
					<div class="col-sm-1 text-end">
						<div class="spinner-border spinner-border-sm" role="status" id="check_status_`+check_name+`_spinner"></div>
					</div>
				</div>
			</div>
		</button>
	</h2>
	<div id="results_accordion_`+check_name+`" class="accordion-collapse collapse show">
		<div class="accordion-body">
			<div class="container-fluid" id="table_`+check_name+`"></div>
		</div>
	</div>
</div>
`;
}

// format a result for display in the results table
function formatResult(data) {
	// when we add one, it should only be shown if the severity matches the filter
	disp =
		severity=="all" || 
		(severity=="info" && data.level>=1) ||
		(severity=="warning" && data.level>=2) ||
		(severity=="error" && data.level>=3);

		return `
<div class="row result_level_`+levelToName(data.level)+`" `+(disp ? "" : "style='display:none;'")+`>
	<div class="col-sm-2">`+data.timestamp.slice("YYYY-MM-DDT".length)+`</div>
	<div class="col-sm-3 text-truncate">`+data.mnemonic+`</div>
	<div class="col-sm-7">`+data.details+`</div>
</div>`;
}

// create a new check status object with all counters set to zero
function newCheckStatus() {
	return {
		detail: 0,
		info: 0,
		warning: 0,
		error: 0,
	};
}

// update the check status display for a given check
// this could be done nicer with value bindings and all
function updateCheckStatus(check_name) {
	$("#check_status_"+check_name).html(`
<span class="result_summary_detail">Detail: `+checkStatuses[check_name].detail+`</span>
<span class="result_summary_info">Info: `+checkStatuses[check_name].info+`</span>
<span class="result_summary_warning">Warning: `+checkStatuses[check_name].warning+`</span>
<span class="result_summary_error">Error: `+checkStatuses[check_name].error+`</span>
`);
}

function finishCheck() {
	$("#check_status_"+check_name+"_spinner").hide()
}

function levelToName(level) {
	switch(level) {
		case 0:
			return "detail";
		case 1:
			return "info";
		case 2:
			return "warning";
		case 3:
			return "error";
		case 4:
			return "fatal";
		case 5:
			return "todo";
		case 6:
			return "admin";
		default:
			return "unknown";
	}
}