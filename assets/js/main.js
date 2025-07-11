var checksList
var checkStatuses = {}
var severity = "warning"

function handleWebsocketRead(data) {
	data = JSON.parse(data);
	check_name = data.check.toLowerCase();
	$("#table_"+check_name).append(formatResult(data));
	checkStatuses["admin"][levelToName(data.level)] += 1;
	checkStatuses[check_name][levelToName(data.level)] += 1;
	if( data.mnemonic == "FINISH" ) {
		finishCheck(check_name);
	}
	updateCheckStatus("admin");
	updateCheckStatus(check_name);
}


$.when( $.ready ).then(function() {
	$.ajax({
				url: '/api/control/checks',
				success: function(data) {
					checksList = data.params;
					showChecksList()
				},
		});

	// websocket data
	webSocket = new WebSocket("http://localhost:8080/api/results/")
	webSocket.onmessage = (event) => {
		handleWebsocketRead(event.data);
	};

	$("#severity_filter").on('change', function() {
		severity = $(this).val();
		switch(severity) {
		case "all":
			$(".result_detail").show();
			$(".result_info").show();
			$(".result_warning").show();
			break;
		case "info":
			$(".result_detail").hide();
			$(".result_info").show();
			$(".result_warning").show();
			break;
		case "warning":
			$(".result_detail").hide();
			$(".result_info").hide();
			$(".result_warning").show();
		default:
			$(".result_detail").hide();
			$(".result_info").hide();
			$(".result_warning").hide();
		}
	});
});

function showChecksList() {
	$('#checkslist').empty();
	if (checksList.length === 0) {
		$('#checkslist').append('<li>No checks available</li>');
	} else {
		checksList.forEach(function(check) {
			$('#checks_list_table').append(`
<tr>
	<td><input class="form-check-input" type="checkbox" id="check_run_`+check+`" checked></td>
	<td><label class="form-check-label" for="check_run_`+check+`">`+check+`</label></td>
</tr>
`);
		});
			$('#checks_list_table').append(`
<tr>
	<td></td>
	<td><input class="btn btn-primary" type="submit" value="Start checks" onclick="startChecks()" id="startbutton" /></td>
</tr>
`);
	}
}

function startChecks() {
	var checksToDo = []
  container = $("#results_accordion")
	items = $("input[type='checkbox']").filter(':checked')
	container.append(checkAccordionItem("admin"));
	checkStatuses["admin"] = newCheckStatus();
	updateCheckStatus("admin");
	for (const [key, value] of Object.entries(items)) {
		if( value.id!=null && value.id.startsWith("check_run_")) {
			check_name = value.id.slice("check_run_".length)
			checksToDo.push(check_name);
  		container.append(checkAccordionItem(check_name));
			checkStatuses[check_name] = newCheckStatus();
			updateCheckStatus(check_name);
	  }
	}

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
	$("#startbutton").html(`<span class="spinner-border spinner-border-sm" aria-hidden="true"></span><span role="status">Running...</span>`);
	$("#startbutton").prop("disabled", true);
}

function checkAccordionItem(check_name) {
return `
<div class="accordion-item">
  <h2 class="accordion-header">
    <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#results_accordion_`+check_name+`">
      `+check_name+`
	  	<div class="ms-auto" id="check_status_`+check_name+`"></div>
	  	<div class="ms-auto" id="check_status_`+check_name+`_spinner">
				<div class="spinner-border spinner-border-sm" role="status"></div>
			</div>
    </button>
  </h2>
  <div id="results_accordion_`+check_name+`" class="accordion-collapse collapse show">
    <div class="accordion-body">
			<table class="table table-sm table-borderless" id="table_`+check_name+`"></table>
		</div>
  </div>
</div>
`;
}

function formatResult(data) {
	disp =
		severity=="all" || 
		(severity=="info" && data.level>=1) ||
		(severity=="warning" && data.level>=2) ||
		(severity=="error" && data.level>=3);

		return `
<tr class="result_`+levelToName(data.level)+`" `+(disp ? "" : "style='display:none;'")+`>
	<td>`+data.timestamp.slice("YYYY-MM-DDT".length)+`</td>
	<td>`+data.mnemonic+`</td>
	<td>`+data.details+`</td>
</tr>`;
}

function newCheckStatus() {
	return {
		detail: 0,
		info: 0,
		warning: 0,
		error: 0,
	};
}

function updateCheckStatus(check_name) {
	$("#check_status_"+check_name).html(`
<span class="result_detail">Detail: `+checkStatuses[check_name].detail+`</span>
<span class="result_info">Info: `+checkStatuses[check_name].info+`</span>
<span class="result_warning">Warning: `+checkStatuses[check_name].warning+`</span>
<span class="result_error">Error: `+checkStatuses[check_name].error+`</span>
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