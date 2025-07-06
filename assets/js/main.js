var checksList
var severity = "warning"

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
	function handleWebsocketRead(data) {
		data = JSON.parse(data);
		$("#table_"+data.check.toLowerCase()).append(formatResult(data));
	}

	$("#severity_filter").on('change', function() {
			severity = $(this).val();
			switch(severity) {
			case "all":
				$(".result_0").show(); //	debug
				$(".result_1").show(); // info
				$(".result_2").show(); // warning
				break;
			case "info":
				$(".result_0").hide(); //	debug
				$(".result_1").show(); // info
				$(".result_2").show(); // warning
				break;
			case "warning":
				$(".result_0").hide(); //	debug
				$(".result_1").hide(); // info
				$(".result_2").show(); // warning
			default:
				$(".result_0").hide(); //	debug
				$(".result_1").hide(); // info
				$(".result_2").hide(); // warning
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
	<td><label class="form-check-label">`+check+`</label></td>
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
	for (const [key, value] of Object.entries(items)) {
		if( value.id!=null && value.id.startsWith("check_run_")) {
			check_name = value.id.slice("check_run_".length)
			checksToDo.push(check_name);
  		container.append(`
<div class="accordion-item">
  <h2 class="accordion-header">
    <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#results_accordion_`+check_name+`">
      `+check_name+`
    </button> 
  </h2>
  <div id="results_accordion_`+check_name+`" class="accordion-collapse collapse show">
    <div class="accordion-body">
			<table class="table table-sm table-borderless" id="table_`+check_name+`"></table>
		</div>
  </div>
</div>
`);
	  }
	}

	$.ajax({
				url: '/api/control/start',
				type: 'POST',
				data: {checks: checksToDo}
		});
	$('#startbutton').text('Starting...');
	$('#startbutton').prop('disabled', true);
}

function formatResult(data) {
	disp =
		severity=="all" || 
		(severity=="info" && data.level>=1) ||
		(severity=="warning" && data.level>=2) ||
		(severity=="error" && data.level>=3);

		return `
<tr class="result_`+data.level+`" `+(disp ? "" : "style='display:none;'")+`>
	<td>`+data.timestamp.slice("YYYY-MM-DDT".length)+`</td>
	<td>`+data.mnemonic+`</td>
	<td>`+data.details+`</td>
</tr>`;
}
