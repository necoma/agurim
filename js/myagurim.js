// configuration variables
var cgi_path = "cgi-bin/";	// path to the cgi-bin directory
var timeoffset = 9;		// time offset
// end of configuration variables

var html = {
	main: 1,
	detail: 2,
	spec: 3
}

new function() {
	var query = {
		criteria: '', 
		dsname: '', 
		view: '',
		interval: 0,
		threshold: 0, 
		nflows: 0, 
		duration: 0, 
		startTime: 0,
		endTime: 0,
		filter: '',
		outfmt: 'json'
	};
	var common = {
		type: 0, // type=1: for main.html, type=2: for detail.html*/
		startTime: 0,	// starTime in previous response */
		endTime: 0,	// endTime in previous response */
		offset: timeoffset	// timezone offset
	};
    var seriesIndex = 0;  // to keep track of series index
	// define global object
	myAgurim = {
		main: function() {
			common.type = html.main;
			myAgurim.sendQuery('packet');
			myAgurim.sendQuery('byte');
		},
		detailMain: function(params) {
			common.type = html.detail;
			if (params != null) {
				myAgurim.parseQuery(params);
			}
			myAgurim.sendQuery(query.criteria);
		},
		detailSpec: function(params) {
			common.type = html.spec;
			myAgurim.parseQuery(params);
			myAgurim.sendQuery(query.criteria);
		},
		sendQuery: function(criteria) {
			$.ajax({
				type: "POST",
				url: cgi_path + "myagurim.cgi",
				datatype: "json",
				data: query,
				beforeSend : function (){
					if (common.type == html.detail) {
						myAgurim.changeURL();
					}
					if (common.type == html.spec) {
						common.type = html.detail;
					}
					query.criteria = criteria;
				}
			})
				.done(function(data) {
					if (query.outfmt == 'json') {
						var response, plotdata;
						console.log("cmd:" + data['cmd']);
						response = myAgurim.parseResponse(data);
						myAgurim.insertTimeLabel(response.startTime, response.endTime, response.interval);
						plotdata = myAgurim.generatePlotData(response.criteria, response.interval, response.nflows, response.labels, response.data);
						myAgurim.visualizeStaticPlot(response.id, response.ylabel, plotdata);
					}
					if (query.outfmt == 'text') {
						var textId = document.getElementById('text');
						textId.innerHTML = "<pre>" + data + "</pre>";
					}
					if (query.outfmt == 'file') {
						var response;
						var startTime = String(myAgurim.TimeStampUpdate(query.startTime * 1000 + (3600000 * common.offset), 0));
						var endTime = String(myAgurim.TimeStampUpdate(query.endTime * 1000 + (3600000 * common.offset), 0));
						var file = startTime + "to" + endTime + ".txt";
						myAgurim.createDWfile(file, data);
					}
				})
				.fail(function(jqXHR, textStatus, errorThrown) {
					console.log("api/sendQuery failed: " + textStatus + ' ' + errorThrown);
					console.log("responsetext: " + jqXHR.responseText);
					myAgurim.resetQuery();
				});
		},

		parseResponse: function(p) {
			var res = {
				criteria: '', 
				interval: 0,
				nflows: 0,
				duration: 0,
				startTime: 0,
				endTime: 0,
				labels: 0,
				data: null,
				ylabel: '',
				id: '',
			};

			res.nflows = parseInt(p.nflows);
			res.interval = parseInt(p.interval);
			res.duration = parseInt(p.duration);
			res.startTime = parseInt(p.start_time);
			res.endTime = parseInt(p.end_time);
			res.labels = p.labels;
			res.data = p.data;
			res.criteria = p.criteria;
			if (res.criteria == 'packet') {
				if (common.type == html.main) {
					res.id = 'PPS';
				}
				res.ylabel = 'Kpps';
			}
			if (res.criteria == 'byte') {
				if (common.type == html.main) {
					res.id = 'BPS';
				}
				res.ylabel = 'Mbps';
			}
			return res;
		},
		insertTimeLabel: function(startTime, endTime, interval) {
			var offset = common.offset;

			var str = myAgurim.TimeStampUpdate(startTime * 1000 + (3600000 * offset), 1) + ' - ' +  
				myAgurim.TimeStampUpdate(endTime * 1000 + (3600000 * offset), 1) + '  UTC+' + offset; 

			str += ' (resolution: ' + String(interval) + 's';
			if (interval < 60)
				str += ')';
			else if (interval < 3600)
				str += ' = ' + (interval/60).toFixed(1) + 'min)';
			else if (interval < 3600*24)
				str += ' = ' + (interval/3600).toFixed(1) + 'hour)';
			else
				str += ' = ' + (interval/3600/24).toFixed(1) + 'day)';

			common.startTime = startTime;
			common.endTime = endTime;

			$('h3.datetime').text(str);
			//$(tag).text(str);
		},
		TimeStampUpdate: function(Utime, needToken) {
			function pad(num) {
				num2 = num.toString();
				return num2.length < 2 ? '0' + num2 : num2;
			}
			var ts = new Date(Utime);
			var YY = ts.getUTCFullYear().toString();
			var MM = pad(ts.getUTCMonth() + 1);
			var dd = pad(ts.getUTCDate());
			var hh = pad(ts.getUTCHours());
			var mm = pad(ts.getUTCMinutes());
			var ss = pad(ts.getUTCSeconds());
			var ret;

			if (needToken) {
				ret = YY + '/' + MM + '/' + dd + ' ' + hh + ':' + mm;
			} else {
				ret = YY + MM + dd + hh + mm;
			}
			return (ret);
		},
		hmsToSecondsOnly: function(str) {
			var p = str.split(':');
			var s = 0, m = 1, i;

			for (i = 2; i >= 0; i--) {
				if (isNaN(p[i]) != true) {
					s += m * parseInt(p[i], 10);
				} 
				m *= 60;
			}
			return s;
		},
		generatePlotData: function(criteria, interval, nflows, labels, data) {
			var unit, offset;
			var val1, val2;
			var ary;

			if (isNaN(nflows) || nflows == 0) {
				console.log("generatePlotData: no data to plot!");
				return null;
			}
			ary = new Array(nflows);
			offset = common.offset;

			for (var i = 0; i <= nflows; i++) {
				ary[i] = {'label': labels[i], 'data': new Array()};
			}
			/* get an unit */
			// XXXkatoon I should decide these units automatically
			if (criteria == 'packet') {
				unit = 1000;
			}
			if (criteria == 'byte') {
				unit = 1000000 / 8;
			}

			/* generate plot data */
			for (var i = 0; i < data.length; i++) {
				val1 = data[i][0] * 1000 + (3600000 * offset);
				for (var j = 0; j <= nflows; j++) {
					val2 = parseInt(data[i][j+1] / (unit * interval));
					ary[j]['data'].push([val1, val2]);
				}
			}
			return ary;
		},
		visualizeStaticPlot: function(id, ylabel, data) {
			// helper for returning the weekends in a period
			function weekendAreas(axes) {
				var markings = [];
				var d = new Date(axes.xaxis.min);
				// go to the first Saturday
				d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 1) % 7))
				d.setUTCSeconds(0);
				d.setUTCMinutes(0);
				d.setUTCHours(0);
				var i = d.getTime();
				do {
					// when we don't set yaxis, the rectangle automatically
					// extends to infinity upwards and downwards
					markings.push({ xaxis: { from: i, to: i + 2 * 24 * 60 * 60
											 * 1000 } });
					i += 7 * 24 * 60 * 60 * 1000;
				} while (i < axes.xaxis.max);

				return markings;
			}

			var lgdcontainer = "#" + id + "legend";  // legend container
			var options = {
				legend: {
					noColumns: 2,
					show: true,
					container: $(lgdcontainer),
				},
				grid: {
					hoverable: false,
					clickable: true,
					markings: weekendAreas
				},
				series: {
					lines: { show: true }
				},
				xaxis: {
					mode: "time",
					timeformat: "%m/%d<br>%H:%M",
					ticks: 6
				},
				yaxis: {
					ticks: 5,
					tickFormatter: function (v) { 
						return (v + ylabel);
					}
				},
				highlightSeries: {
        			color: "black",
        			_optimized: true
				}
			};

			if (data == null) {
				return;			// no data to plot
			}

		    if (common.type == html.detail) {
			    options["selection"] = { mode: "xy" };
			}
			options["legend"]["labelFormatter"] = myAgurim.labelFunc;
			seriesIndex = 0;  // reset index for a new plot

			var placeholder = "#" + id + "chart";
			var plot = $.plot($(placeholder), data, options);

			// legend actions
			$(lgdcontainer).on({
				'mouseenter': function () {
					// console.log("mouseenter: " + $(this).find('p').attr("seriesIndex"));
					$(this).css("background", "lavender");
					// XXX need to map legend to series index
					var idx = parseInt($(this).find('p').attr("seriesIndex"));
					if (!isNaN(idx)) {
						plot.highlightSeries(idx);
					}
				},
				'mouseleave': function () {
					// console.log("mouseleave: " + $(this).find('p').attr("seriesIndex"));
					$(this).css("background", "");
					var idx = parseInt($(this).find('p').attr("seriesIndex"));
					if (!isNaN(idx)) {
						plot.unHighlightSeries(idx);
					}
				},
				'click': function () {
					var flowstr = $(this).text().replace(/\s*(\S.+?) \d+\.\d+\%.*/, "\$1");
					// console.log("click:" + flowstr);
					if (common.type == html.detail && flowstr != "TOTAL") {
						myAgurim.filterFlow(flowstr);
					}
				}
			}, "table tr td");

			// jump to the detail page on click
			$(placeholder).on("plotclick", function (event, pos, item) {
				// console.log("plot clicked:" + placeholder);
				if (placeholder == "#BPSchart") {
					query.criteria = 'byte';
				} else if (placeholder == "#PPSchart") {
					query.criteria = 'packet';
				}
				var qstr = $.param(query);
				window.location.href = "detail.html" + '?' + qstr;
			});

			/* zoom into selected area */
			if (common.type == html.detail) {
				$(placeholder).on("plotselected", function (event, ranges) {
					var stime, duration;
					stime = ranges.xaxis.from / 1000 - (3600 * common.offset);
					stime = ~~((stime + 300) / 600) * 600;  // round to 10min.
					query.startTime = stime;
					duration = (ranges.xaxis.to - ranges.xaxis.from) / 1000;
					duration = ~~((duration + 300) / 600) * 600; // ditto
					query.duration = duration;
				});
			}
		},
		labelFunc: function(label, series) {
			var dim2flow = label.toString().replace(/\[(.*?)\]\s*(\S.*?)  \[(.*)$/, "\$2");
			var proto = label.toString().replace(/\[(.*?)\](.*?)\%  \[(.*)/, "\[\$3");
			var newlabel = '';
			
			newlabel = '<br><p seriesIndex="' + seriesIndex + '"><b>' + String(dim2flow) + '</b><br>';
			if (dim2flow != "TOTAL") {
				newlabel += proto;
			}
			newlabel += '</p>';
			seriesIndex++;  // increment series index
			return (newlabel);
		},
		filterFlow: function(flow) {
			if (query.view == 'proto') {
			    query.filter = flow.replace(/(\S+) (\S+)/, '\$1');
		    	} else {
			    query.filter = flow.replace(/(\S+) (\S+) (\S+)/, '\$1 \$2');
			}
			myAgurim.sendQuery(query.criteria);
		},
		isNumber: function(n) {
			return !isNaN(parseFloat(n)) && isFinite(n);
		},
		parseQuery: function(ary) {
			var res;

			console.log("parseQuery:" + ary);
			for (var i = 0; i < ary.length; i++) {
				res = ary[i].split("=");

				if (res[0] == "criteria") {
					query.criteria = res[1];
				} else if (res[0] == "dsname") {
					query.dsname = res[1];
				} else if (res[0] == "view") {
					query.view = res[1];
				} else if (res[0] == "interval") {
					var val = parseInt(res[1]);
					query.interval = isNaN(val) ? 0 : val;
				} else if (res[0] == "threshold") {
					var val = parseInt(res[1]);
					query.threshold = isNaN(val) ? 0 : val;
				} else if (res[0] == "nflows") {
					var val = parseInt(res[1]);
					query.nflows = isNaN(val) ? 0 : val;
				} else if (res[0] == "duration") {
					var val = parseInt(res[1]);
					query.duration = isNaN(val) ? 0 : val;
				} else if (res[0] == "startTime") {
					if (String(res.slice(1))) {
						var str = String(res.slice(1));
						var res2 = str.split("T");
						if (myAgurim.isNumber(str)) {
							// user input is unix timestamp
							query.startTime = parseInt(str);
						} else {
							// user input is formal timestamp
							query.startTime = new Date(String(res2[0])).getTime()/1000 - (3600 * common.offset);
							if (res2.length > 1) {
								query.startTime += myAgurim.hmsToSecondsOnly(String(res2[1]));
							}
						}
					} else {
						query.startTime = 0;
					}
				} else if (res[0] == "endTime") {
					if (String(res.slice(1))) {
						var str = String(res.slice(1));
						var res2 = str.split("T");
						if (myAgurim.isNumber(str)) {
							// user input is unix timestamp
							query.endTime = parseInt(str);
						} else {
							// user input is formal timestamp
							query.endTime = new Date(String(res2[0])).getTime()/1000 - (3600 * common.offset);
							if (res2.length > 1) {
								query.endTime += myAgurim.hmsToSecondsOnly(String(res2[1]));
							}
						}
					} else {
						query.endTime = 0;
					}
				} else if (res[0] == "outfmt") {
					query.outfmt = res[1];
				}
			}
		},
		changeURL: function() {
			var str = '';

			// add a criteria parameter
			str += 'criteria=' + query.criteria;
			// add out format 
			str += '&outfmt=' + query.outfmt;

			// add dsname
			if (query.dsname) {
				str += '&dsname=' + query.dsname;
			}
			// add view
			if (query.view) {
				str += '&view=' + query.view;
			}
			// add this flow filter if exists
			if (query.filter != '') {
				str += '&filter=' + query.filter;
			}
			// add duration parameter
			if (query.duration != 0) {
				str += '&duration=' + query.duration;
			}
			// add interval parameter
			if (query.interval != 0) {
				str += '&interval=' + query.interval;
			}
			// add nflow parameter
			if (query.nflows != 0) {
				str += '&nflow=' + query.nflows;
			}

			// add start time stamp
			if (query.startTime != 0) {
				str += '&startTime=' + query.startTime;
			}
			// add end time stamp
			if (query.endTime != 0) {
				str += '&endTime=' + query.endTime;
			}

			if (window.history && window.history.pushState) {
				if (typeof window.history.pushState == 'function') {
					//history.replaceState({}, str, window.location.pathname + '?' + str);
					history.pushState(str, null, window.location.pathname + '?' + str);
				}
			}
		},
		/* Actions for button */
		resetQuery: function() {
			query.criteria = '';
			query.dsname = '';
			query.view = '';
			query.interval = 0;
			query.threshold = 0;
			query.nflows = 0;
			query.duration = 0;
			query.startTime = 0;
			query.endTime = 0; // katoon 1389711600 (= 2014/01/14T00:00:00)
		},
		/* Actions for button */
		back: function() {
			// if start is not aligned, align it.  otherwise, move start.
			query.endTime = 0;
			if (query.duration == 0) {
				query.duration = 86400;
			}
			if (query.startTime == 0) {
				query.startTime = common.startTime;	// use previous response
			}
			if (query.duration < 86400 * 7) {
				mod = (query.startTime + common.offset * 3600) % query.duration;
				if (mod != 0) {
					query.startTime -= mod;
				} else {
					query.startTime -= query.duration;
				}
			} else {
				// need to use Date objects for week, month or year
				var date = new Date(query.startTime * 1000);
				var yyyy = date.getFullYear();
				var mm = date.getMonth();
				var dd = date.getDate();
				var yyyy2 = yyyy, mm2 = 0, dd2 = 1;
				var day1, day2;
				if (query.duration == 86400 * 7) {
					var day = date.getDay();
					if (day != 0) {
						dd -= day;
					} else {
						dd -= 7;
					}
					dd2 = dd + 7; mm2 = mm;
				} else if (query.duration <= 86400 * 31 * 6) {
					if (dd != 1) {
						dd = 1;
					} else {
						mm -= 1;
					}
					if (query.duration <= 86400 * 31 * 1) {
						mm2 = mm + 1;
					} else if (query.duration <= 86400 * 31 * 3) {
						mm -= 2;
						mm2 = mm + 3;
					} else {
						mm -= 5;
						mm2 = mm + 6;
					}
				} else {
					if (mm != 0 || dd != 1) {
						mm = 0; dd = 1;
					} else {
						yyyy -= 1;
					}
					yyyy2 = yyyy + 1;
				}
				day1 = new Date(yyyy, mm, dd);
				day2 = new Date(yyyy2, mm2, dd2);
				query.startTime = day1.getTime() / 1000;
				query.duration = (day2.getTime() - day1.getTime()) / 1000;
			}

			if (common.type == html.main) {
				myAgurim.main();
			} else if (common.type == 2) {
				myAgurim.detailMain();
			}
		},
		forward: function() {
			// if start is not aligned, align it.  otherwise, move start.
			query.endTime = 0;
			if (query.duration == 0) {
				query.duration = 86400;
			}
			if (query.startTime == 0) {
				query.startTime = common.startTime;	// use previous response
			}
			if (query.duration < 86400 * 7) {
				mod = (query.startTime + common.offset * 3600) % query.duration;
				if (mod != 0) {
					query.startTime += query.duration - mod;
				} else {
					query.startTime += query.duration;
				}
			} else {
				// need to use Date objects for week, month or year
				var date = new Date(query.startTime * 1000);
				var yyyy = date.getFullYear();
				var mm = date.getMonth();
				var dd = date.getDate();
				var yyyy2 = yyyy, mm2 = 0, dd2 = 1;
				var day1, day2;
				if (query.duration == 86400 * 7) {
					var day = date.getDay();
					if (day != 0) {
						dd += 7 - day;
					} else {
						dd += 7;
					}
					dd2 = dd + 7; mm2 = mm;
				} else if (query.duration <= 86400 * 31 * 6) {
					dd = 1;
					if (query.duration <= 86400 * 31 * 1) {
						mm += 1;
						mm2 = mm + 1;
					} else if (query.duration <= 86400 * 31 * 3) {
						mm += 3;
						mm2 = mm + 3;
					} else {
						mm += 3;
						mm2 = mm + 6;
					}
				} else {
					mm = 0; dd = 1;
					yyyy += 1;
					yyyy2 = yyyy + 1;
				}
				day1 = new Date(yyyy, mm, dd);
				day2 = new Date(yyyy2, mm2, dd2);
				query.startTime = day1.getTime() / 1000;
				query.duration = (day2.getTime() - day1.getTime()) / 1000;
			}

			if (common.type == 1) {
				myAgurim.main();
			} else if (common.type == 2) {
				myAgurim.detailMain();
			}
		},
		zoomIn: function() {
			if (query.duration == 0) {
				query.duration = 86400;
			}
			if (query.duration > 86400 * 180) {
				query.duration = 86400 * 180;
			} else if (query.duration > 86400 * 93) {
				query.duration = 86400 * 90;
			} else if (query.duration > 86400 * 31) {
				query.duration = 86400 * 31;
			} else if (query.duration > 86400 * 7) {
				query.duration = 86400 * 7;
			} else if (query.duration > 86400) {
				query.duration = 86400;
			} else if (query.duration > 21600) {
				query.duration = 21600;
			} else {
				query.duration = 3600;
			} 

			if (common.type == 1) {
				myAgurim.main();
			} else if (common.type == 2) {
				myAgurim.detailMain();
			}
		},
		zoomOut: function() {
			if (query.duration == 0) {
				query.duration = 86400;
			}
			if (query.duration < 21600) {
				query.duration = 21600;
			} else if (query.duration < 86400) {
				query.duration = 86400;
			} else if (query.duration < 86400 * 7) {
				query.duration = 86400 * 7;
			} else if (query.duration < 86400 * 28) {
				query.duration = 86400 * 31;
			} else if (query.duration < 86400 * 90) {
				query.duration = 86400 * 90;
			} else if (query.duration < 86400 * 180) {
				query.duration = 86400 * 180;
			} else {
				query.duration = 86400 * 365;
			} 
		    if (query.startTime != 0) {
				// if the endtime exceeds the current time, clear starttime
				var now = new Date().getTime() / 1000;
				if (query.startTime + query.duration > now) {
					query.startTime = 0;
				}
			}

			if (common.type == 1) {
				myAgurim.main();
			} else if (common.type == 2) {
				myAgurim.detailMain();
			}
		},
		download: function() {
			query.outfmt = 'file';
			myAgurim.sendQuery(query.criteria);
		},
		selectds: function(dsname) {
			query.dsname = dsname;
		},
		getds: function() {
			return query.dsname;
		},
		selectView: function(view) {
			query.view = view;
		},
		getView: function() {
			return query.view;
		},
		createDWfile: function(filename, text) {
			var pom = document.createElement('a');
			pom.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
			pom.setAttribute('download', filename);
			pom.click();
		}
	}
}
