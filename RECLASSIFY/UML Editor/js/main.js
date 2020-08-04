
var saveLinkView;
var saveElementView;
// Model //
var graph = new joint.dia.Graph;

// View //
var paper = new joint.dia.Paper({
    el: document.getElementById('paper'),
    model: graph,
    width: 1000,
    height: 700,
    drawGrid: true,
    gridSize: 10,
    backgroundColor: 'white',
    interactive: true,
    highlighting: {
        'default': {
            name: 'stroke',
            options: {
                padding: 20,
            }
        }},

});

/////////////////////////////////

var draggableElementContainerGraph = new joint.dia.Graph;

var draggableElementContainerPaper = new joint.dia.Paper({
    el: document.getElementById('draggableElementContainerPaper'),
    drawGrid: true,
    gridSize: 10,
    width: 150,
    height: 700,
    model: draggableElementContainerGraph,
    interactive: false,
    background: {
        color: '#ecf8ec',
        opacity: 0.3
    }
});
///////////////////////////////////////////

// Connessione tra due elementi //
var connect = function(source, sourcePort, target, targetPort) {

    var link = new joint.dia.Link({
        source: {
            id: source.id,
            port: sourcePort
        },
        target: {
            id: target.id,
            port: targetPort
        }
    });

    link.addTo(graph).reparent();
};
/////////////////////////////////

var previousCellView = null;



paper.on('element:pointerdown',
    function(elementView, evt, x, y) {
        elementView.highlight();

        if(elementView != previousCellView && previousCellView != null){
            previousCellView.unhighlight();
        }
        previousCellView = elementView;
    }
);

paper.on('element:pointerdblclick',function(elementView, evt, x, y) {
    $('#elementModal').modal("show");
    saveElementView = elementView;

    var classname = elementView.model.get("name");
    var attributes = elementView.model.get("attributes");
    var methods = elementView.model.get("methods");

    $('#classname').val(classname);

    var i=0;
    var attributes_html = '';
    attributes.forEach(function(attribute){
        attributes_html += '<div id="attribute-'+i+'" ><input type="text" class="form-control " id="attribute" style="width:160px;" value="'+attribute+'"><button type="button" class="close" style="margin-top:5px;" onclick="attribute_remove('+i+');"><span class="glyphicon glyphicon-remove text-danger" aria-hidden="true"></span></button></div>';
        i = i+1;
    });
    $('#attributes').html(attributes_html);

    i=0;
    var methods_html = '';
    methods.forEach(function(method){
        methods_html += '<div id="method-'+i+'" ><input type="text" class="form-control" id="method" style="width:160px;" value="'+method+'"><button type="button" class="close" style="margin-top:5px;" onclick="method_remove('+i+');"><span class="glyphicon glyphicon-remove text-danger" aria-hidden="true"></span></button></div>';
        i = i+1;
    });
    $('#methods').html(methods_html);   

});

$('#attributes-plus').click(function(){
    var attribute_inputs = $('#attributes :input');
    var id = attribute_inputs.length;
    var attributes_html = '<div id="attribute-'+id+'" ><input type="text" class="form-control " id="attribute" style="width:160px;" ><button type="button" class="close" style="margin-top:5px;" onclick="attribute_remove('+id+');" ><span class="glyphicon glyphicon-remove text-danger" aria-hidden="true"></span></button></div>';
    $('#attributes').append(attributes_html);
});

$('#methods-plus').click(function(){
    var method_inputs = $('#methods :input');
    var id = method_inputs.length;
    var methods_html = '<div id="method-'+id+'" ><input type="text" class="form-control " id="method" style="width:160px;"><button type="button" class="close" style="margin-top:5px;" onclick="method_remove('+id+');"><span class="glyphicon glyphicon-remove text-danger" aria-hidden="true"></span></button></div>';
    $('#methods').append(methods_html);
});

function attribute_remove(id){
    $("#attribute-"+id).remove();
}

function method_remove(id){
    $("#method-"+id).remove();
}

$('#SaveElement').click(function(){
    var oldname = saveElementView.model.get("name");
    var classname = $('#classname').val();
    saveElementView.model.setName(classname);

    var attribute_inputs = $(':input[id="attribute"]');
    var attributes = [];
    attribute_inputs.each(function(){
        attributes.push($(this).val());
    });
    saveElementView.model.setAttributes(attributes);

    var method_inputs = $(':input[id="method"]');
    var methods = [];
    method_inputs.each(function(){
        methods.push($(this).val());
    });
    saveElementView.model.setMethods(methods);
    saveElementView.update();
    saveElementView.resize();

    var links = graph.getLinks();
    links.forEach(function(link){
        if(link.attributes.source.id == oldname){
            link.attributes.source.id = classname;
        }else if(link.attributes.target.id == oldname){
            link.attributes.target.id = classname;
        }
    });

    $('#elementModal').modal("hide");
});

paper.on('link:pointerdblclick', function(linkView) {
   $('#linkModal').modal("show");
   saveLinkView = linkView;
   var labels = linkView.model.labels();
   if (labels.length != 0){
       var label = labels[0].attrs.text.text;
       $('#label').val(label);
   }
   
});

$('#SaveLink').click(function(){
    var label = $('#label').val();
    saveLinkView.model.labels([{
                        attrs: {
                            text: {
                                text: label
                            }
                        }
                    }]);
    $('#linkModal').modal("hide");
});
///////////////////////////////////////////

// Click sul piano //
paper.on('blank:pointerdown',
    function(evt, x, y) {

        selected = null;
        $('#delete').prop('disabled', true);
        $('#modifica').prop('disabled', true);
        $('#textA').prop('disabled', true);
        $('#textA').val("");

        if(previousCellView != null){
            previousCellView.unhighlight();
            //console.log("unhighlighted "+previousCellView.model.id);
        }
    }
);
///////////////////////////////////////////
var uml = joint.shapes.uml;
var cells = [];

// Elementi UML //
/*
// Interfaccia UML //
var Interfaccia = new uml.Interface({
      position: { x:10  , y: 30 },
      size: { width: 130, height: 120 },
      name: 'Interfaccia',
      attributes: ['- stato: tipo'],
      methods: ['+metodo(): tipo'],
      attrs: {
          '.uml-class-name-rect': {
              fill: '#feb662',
              stroke: '#ffffff',
              'stroke-width': 0.5
          },
          '.uml-class-attrs-rect, .uml-class-methods-rect': {
              fill: '#fdc886',
              stroke: '#fff',
              'stroke-width': 0.5
          },
          '.uml-class-attrs-text': {
              ref: '.uml-class-attrs-rect',
              'ref-y': 0.5,
              'y-alignment': 'middle'
          },
          '.uml-class-methods-text': {
              ref: '.uml-class-methods-rect',
              'ref-y': 0.5,
              'y-alignment': 'middle'
          }

      }
  });
cells[0] = Interfaccia;

// Classe Astratta  UML //
var ClasseAstratta = new uml.Abstract({
    position: { x:10  , y: 180 },
    size: { width: 130, height: 120 },
    name: 'Classe Astratta',
    attributes: [' - stato:tipo'],
    methods: ['+ metodo(): tipo'],
    attrs: {
        '.uml-class-name-rect': {
            fill: '#68ddd5',
            stroke: '#ffffff',
            'stroke-width': 0.5
        },
        '.uml-class-attrs-rect, .uml-class-methods-rect': {
            fill: '#9687fe',
            stroke: '#fff',
            'stroke-width': 0.5
        },
        '.uml-class-methods-text, .uml-class-attrs-text': {
            fill: '#fff'
        }
    }
});
cells[1] = ClasseAstratta;
*/
/*
joint.shapes.basic.Generic.define("uml.Class", {
    attrs: {
        rect: {
            width: 200
        },
        ".uml-class-name-rect": {
            stroke: "black",
            "stroke-width": 2,
            fill: "#3498db"
        },
        ".uml-class-attrs-rect": {
            stroke: "black",
            "stroke-width": 2,
            fill: "#2980b9"
        },
        ".uml-class-methods-rect": {
            stroke: "black",
            "stroke-width": 2,
            fill: "#2980b9"
        },
        ".uml-class-name-text": {
            ref: ".uml-class-name-rect",
            "ref-y": .5,
            "ref-x": .5,
            "text-anchor": "middle",
            "y-alignment": "middle",
            "font-weight": "bold",
            fill: "black",
            "font-size": 12,
            "font-family": "Times New Roman"
        },
        ".uml-class-attrs-text": {
            ref: ".uml-class-attrs-rect",
            "ref-y": 5,
            "ref-x": 5,
            fill: "black",
            "font-size": 12,
            "font-family": "Times New Roman"
        },
        ".uml-class-methods-text": {
            ref: ".uml-class-methods-rect",
            "ref-y": 5,
            "ref-x": 5,
            fill: "black",
            "font-size": 12,
            "font-family": "Times New Roman"
        }
    },
    name: [],
    attributes: [],
    methods: []
},
{
    markup: ['<g class="rotatable">', '<g class="scalable">', '<rect class="uml-class-name-rect"/><rect class="uml-class-attrs-rect"/><rect class="uml-class-methods-rect"/>', "</g>", '<text class="uml-class-name-text"/><text class="uml-class-attrs-text"/><text class="uml-class-methods-text"/>', "</g>"].join(""),
    initialize: function() {
        this.on("change:name change:attributes change:methods",
        function() {
            this.updateRectangles(),
            this.trigger("uml-update")
        },
        this),
        this.updateRectangles(),
        joint.shapes.basic.Generic.prototype.initialize.apply(this, arguments)
    },
    getClassName: function() {
        return this.get("name")
    },
    updateRectangles: function() {
        var a = this.get("attrs"),
        b = [{
            type: "name",
            text: this.getClassName()
        },
        {
            type: "attrs",
            text: this.get("attributes")
        },
        {
            type: "methods",
            text: this.get("methods")
        }],
        c = 0;
        b.forEach(function(b) {
            var d = Array.isArray(b.text) ? b.text: [b.text],
            e = 20 * d.length + 20;
            a[".uml-class-" + b.type + "-text"].text = d.join("\n"),
            a[".uml-class-" + b.type + "-rect"].height = e,
            a[".uml-class-" + b.type + "-rect"].transform = "translate(0," + c + ")",
            c += e
        })
    }
}),
joint.shapes.uml.ClassView = joint.dia.ElementView.extend({
    initialize: function() {
        joint.dia.ElementView.prototype.initialize.apply(this, arguments),
        this.listenTo(this.model, "uml-update",
        function() {
            this.update(),
            this.resize()
        })
    }
}),

*/



/*

joint.dia.Link.define("uml.Generalization", {
    attrs: {
        ".marker-target": {
            d: "M 20 0 L 0 10 L 20 20 z",
            fill: "white"
        }
    }
}),
joint.dia.Link.define("uml.Implementation", {
    attrs: {
        ".marker-target": {
            d: "M 20 0 L 0 10 L 20 20 z",
            fill: "white"
        },
        ".connection": {
            "stroke-dasharray": "3,3"
        }
    }
}),
joint.dia.Link.define("uml.Aggregation", {
    attrs: {
        ".marker-target": {
            d: "M 40 10 L 20 20 L 0 10 L 20 0 z",
            fill: "white"
        }
    }
}),
joint.dia.Link.define("uml.Composition", {
    attrs: {
        ".marker-target": {
            d: "M 40 10 L 20 20 L 0 10 L 20 0 z",
            fill: "black"
        }
    }
}),
joint.dia.Link.define("uml.Association"),
*/

joint.shapes.uml.Class.define("uml.MyClass",
{
    attrs: {
        '.uml-class-name-rect': {
            fill: '#ff8450',
            stroke: '#fff',
            'stroke-width': 0.5
        },
        '.uml-class-attrs-rect': {
            fill: '#fe976a',
            stroke: '#fff',
            'stroke-width': 0.5
        },
        '.uml-class-methods-rect': {
            fill: '#fe976a',
            stroke: '#fff',
            'stroke-width': 0.5
        },
        '.uml-class-attrs-text': {
            'ref-y': 0.5,
            'y-alignment': 'middle'
        }
    }
},
{
    setName: function(name) {
        this.set("name",name);
    },
    setAttributes: function(attributes) {
        this.set("attributes",attributes);
    },
    setMethods: function(methods) {
        this.set("methods",methods);
    },
    setSize: function(size) {
        this.set("size",{width:size.width,height:size.height});
    },
    updateRectangles: function() {
        var a = this.get("attrs"),
        b = [{
            type: "name",
            text: this.getClassName()
        },
        {
            type: "attrs",
            text: this.get("attributes")
        },
        {
            type: "methods",
            text: this.get("methods")
        }];
        height = 0;
        width = 0;
        textnum = 0;
        b.forEach(function(b) {
            if(Array.isArray(b.text)){
                height += 15 * b.text.length;
                b.text.forEach(function(text){
                    if (textnum < text.length){
                        textnum = text.length;
                    }
                });
            }else{
                height += 15;
                if (textnum < b.text.length){
                    textnum = b.text.length;
                }
            }
        });
        if (height < 150){
            height = height -15 + 40;
        }
        width = textnum * 5 + 60;
        this.set("size",{width:width,height:height});
        c = 0;
        b.forEach(function(b) {
            var d = Array.isArray(b.text) ? b.text: [b.text],
            e = 20 * d.length + 20;
            a[".uml-class-" + b.type + "-text"].text = d.join("\n"),
            a[".uml-class-" + b.type + "-rect"].height = e,
            a[".uml-class-" + b.type + "-rect"].transform = "translate(0," + c + ")",
            c += e
        })

        
    }
}
);
var Class = new uml.MyClass({position: { x:10  , y: 30 }});
Class.setName("Class");
Class.setAttributes(["attributes"]);
Class.setMethods(["methods"]);
Class.setSize({width:130,height:120});
cells[0] = Class;



// Connessioni UML //
joint.dia.Link.define("uml.Association",{
    attrs: {
        '.connection': { stroke: 'black', strokeWidth: '1' },
        '.marker-target': {
            stroke: 'black',
            strokeWidth: 2,
            fill: 'black',
            d: 'M 10 0 L 0 5 M 0 5 L 10 10'
        }
    }
});
var Association = new uml.Association({source: { x: 75, y:250 }, target: { x:75, y: 170 },router:{name: 'metro'},connector: {name: 'rounded'}});
cells[1] = Association
var Generalization = new uml.Generalization({ source: { x: 75, y:350 }, target: { x:75, y: 270 },router:{name: 'metro'},connector: {name: 'rounded'}});
cells[2] = Generalization
var Aggregation = new uml.Aggregation({ source: { x: 75, y:450 }, target: { x:75, y: 370 },router:{name: 'metro'},connector: {name: 'rounded'}});
cells[3] = Aggregation
var Composition = new uml.Composition({ source: { x: 75, y:550 }, target: { x:75, y: 470 },router:{name: 'metro'},connector: {name: 'rounded'}});
cells[4] = Composition
var Implementation = new uml.Implementation({ source: { x: 75, y:650 }, target: { x:75, y: 570 },router:{name: 'metro'},connector: {name: 'rounded'}});
cells[5] = Implementation
// Aggiungo gli elementi alla draggable Area //
draggableElementContainerGraph.addCells(cells);
///////////////////////////////////////////

///////////////////////////////

// Draggable Area //
draggableElementContainerPaper.on('cell:pointerdown', function(cellView, e, x, y) {
    $('body').append('<div id="flyPaper" style="position:relative;opacity:0.4;pointer-event:none;"></div>');
    var flyGraph = new joint.dia.Graph,
        flyPaper = new joint.dia.Paper({
            el: $('#flyPaper'),
            model: flyGraph,
            height: 100,
            width:110,
            interactive: false
        }),
    flyShape = cellView.model.clone(),
    isElement = flyShape.isElement();
    if (isElement){
        pos = cellView.model.position(),
        offset = {
            x: x - pos.x,
            y: y - pos.y
        };
        flyShape.position(15, 10);
        flyShape.prop = 1;
        flyGraph.addCell(flyShape);
        $("#flyPaper").offset({
            left: e.pageX - offset.x,
            top: e.pageY - offset.y
        });
        $('body').on('mousemove.fly', function(e) {
            $("#flyPaper").offset({
                left: e.pageX - offset.x,
                top: e.pageY - offset.y
            });
        });
        $('body').on('mouseup.fly', function(e) {
            var x = e.pageX,
                y = e.pageY,
                target = paper.$el.offset();

            // Dropped over paper ?
            if (x > target.left && x < target.left + paper.$el.width() && y > target.top && y < target.top + paper.$el.height()) {
                var s = flyShape.clone();
                s.position(x - target.left - offset.x, y - target.top - offset.y);
                graph.addCell(s);
            }
            $('body').off('mousemove.fly').off('mouseup.fly');
            flyShape.remove();
            $('#flyPaper').remove();
        });
    }else{
        pos = cellView.model.target();
        offset = {
            x: x - pos.x,
            y: y - pos.y
        };
        flyShape.target({x:15, y:10});
        flyShape.source({x:15, y:90})
        flyShape.prop = 1;
        flyGraph.addCell(flyShape);
        $("#flyPaper").offset({
            left: e.pageX - offset.x,
            top: e.pageY - offset.y
        });
        $('body').on('mousemove.fly', function(e) {
            $("#flyPaper").offset({
                left: e.pageX - offset.x,
                top: e.pageY - offset.y
            });
        });
        $('body').on('mouseup.fly', function(e) {
            var x = e.pageX,
                y = e.pageY,
                target = paper.$el.offset();
            // Dropped over paper ?
            if (x > target.left && x < target.left + paper.$el.width() && y > target.top && y < target.top + paper.$el.height()) {
                var s = flyShape.clone();
                s.target({x:x - target.left - offset.x, y:y - target.top - offset.y});
                s.source({x:x - target.left - offset.x, y:y - target.top - offset.y + 80});
                graph.addCell(s);
            }
            $('body').off('mousemove.fly').off('mouseup.fly');
            flyShape.remove();
            $('#flyPaper').remove();
        });
    }
});


paper.on('cell:pointerdown', function(cellView, e, x, y) {
    $('body').on('mousemove.fly', function(e) {
        isElement = cellView.model.isElement();
        if (isElement){
            pos = cellView.model.position();
            size = cellView.model.get("size");
            x = pos.x + size.width;
            y = pos.y + size.height;
        }else{
            pos_1 = cellView.model.target();
            pos_2 = cellView.model.source();
            if (pos_1.x > pos_2.x){
                x = pos_1.x;
            }else{
                x = pos_2.x;
            }
            if (pos_1.y > pos_2.y){
                y = pos_1.y;
            }else{
                y = pos_2.y;
            }
        }
        if (x > paper.$el.width()){
            paper.$el.width(paper.$el.width()+500);
            //$('#navbar').width($('#navbar').width()+500);

        }else if (y > paper.$el.height()){
            paper.$el.height(paper.$el.height()+500);
        }
        // TODO: 只能增加不能减少
        //console.log(x,y);
        //console.log(paper.$el.width(),paper.$el.height());
    });
    $('body').on('mouseup.fly', function(e) {
        $('body').off('mousemove.fly').off('mouseup.fly');
    });
    /*
    
    */
    
});

//////////////////////////////////

// BUTTON FUNCTION /////////////////////
$('#deleteAll').on('click', function() {
    graph.clear();
});

$('#DeleteElement').on('click', function() {
    saveElementView.remove();
});
$('#DeleteLink').on('click', function() {
    saveLinkView.remove();
});







//////////////////////////////////////

//点击导入按钮,使files触发点击事件,然后完成读取文件的操作
$("#fileImport").click(function () {
    $("#file_import").click();
})
function fileImport() {
    //获取读取我文件的File对象
    var selectedFile = document.getElementById('file_import').files[0];
    var name = selectedFile.name;//读取选中文件的文件名
    var size = selectedFile.size;//读取选中文件的大小
    //console.log("文件名:"+name+"大小:"+size);

    var reader = new FileReader();//这是核心,读取操作就是由它完成.
    reader.readAsText(selectedFile);//读取文件的内容,也可以读取文件的URL
    reader.onload = function () {
        //当读取完成后回调这个函数,然后此时文件的内容存储到了result中,直接操作即可
        var CHT = JSON.parse(this.result);
        //console.log(CHT);

        var elements = [];
        var links = [];
        //var tempElement = [];
        //var tempLink = [];
        var i=0;
        var j=0;
        Object.keys(CHT).forEach(function(derivedLabel){
            elements[i] = new uml.MyClass({id:derivedLabel});
            elements[i].setName(derivedLabel);
            if (CHT[derivedLabel].hasOwnProperty("object_member")){
                elements[i].setAttributes(CHT[derivedLabel]["object_member"]);
            }
            if (CHT[derivedLabel].hasOwnProperty("function_list")){
                elements[i].setMethods(CHT[derivedLabel]["function_list"]);
            }
            //elements.push(tempElement[i]);
            i = i + 1;

            CHT[derivedLabel]["base"].forEach(function(parentLabel){
                links[j] = new uml.Generalization({ source: { id:derivedLabel }, target: { id:parentLabel },router:{name: 'metro'},connector: {name: 'rounded'}});
                //links[j] = new uml.Generalization({ source: { id:derivedLabel }, target: { id:parentLabel },router:{name: 'manhattan'},connector: {name: 'normal'}});
                if (CHT[derivedLabel].hasOwnProperty("virtual_inherit")){
                    links[j].appendLabel({
                        attrs: {
                            text: {
                                text: 'virtual_inherit'
                            }
                        }
                    });
                }
                j = j + 1;
            });
            if (CHT[derivedLabel].hasOwnProperty("object_member")){
                CHT[derivedLabel]["object_member"].forEach(function(object_member){
                    links[j] = new uml.Association({source: { id:derivedLabel }, target: { id:object_member },router:{name: 'metro'},connector: {name: 'rounded'}});
                    //links[j] = new uml.Association({source: { id:derivedLabel }, target: { id:object_member },router:{name: 'manhattan'},connector: {name: 'rounded'}});
                    links[j].appendLabel({
                        attrs: {
                            text: {
                                text: 'object_member'
                            }
                        }
                    });
                    j = j + 1;
                });
            }
            
        });
        var cells = elements.concat(links);
        //console.log(cells);
        paper.freeze();
        //graph.clear();
        joint.layout.DirectedGraph.layout(cells, {
            rankSep: 100,
            rankDir: "BT"
        });

        graph.resetCells(cells);

        paper.fitToContent({
            padding: 50,
            allowNewOrigin: 'any',
            useModelGeometry: true
        });

        paper.unfreeze();
    }
}

$("#fileExport").click(function () {
    var elements = graph.getElements();
    var links = graph.getLinks();
    var json_data = {};
    elements.forEach(function(element){
        json_data[element.attributes.name] = {};
        json_data[element.attributes.name].function_list = element.attributes.methods;
        json_data[element.attributes.name].base = [];
    });
    
    links.forEach(function(link){
        if(link.attributes.type == "uml.Generalization"){
            json_data[link.attributes.source.id].base.push(link.attributes.target.id);
            if(link.attributes.hasOwnProperty("labels")){
                if (!json_data[link.attributes.source.id].hasOwnProperty(link.attributes.labels[0].attrs.text.text)){
                    json_data[link.attributes.source.id][link.attributes.labels[0].attrs.text.text] = [];
                }
                json_data[link.attributes.source.id][link.attributes.labels[0].attrs.text.text].push(link.attributes.target.id) ;
            }
        }else if(link.attributes.type == "uml.Association"){
            if(link.attributes.hasOwnProperty("labels")){
                if (!json_data[link.attributes.source.id].hasOwnProperty(link.attributes.labels[0].attrs.text.text)){
                    json_data[link.attributes.source.id][link.attributes.labels[0].attrs.text.text] = [];
                }
                json_data[link.attributes.source.id][link.attributes.labels[0].attrs.text.text].push(link.attributes.target.id) ;
            }
        }
    });
    //console.log(json_data);
    data = JSON.stringify(json_data);
    exportfile('RECLASSIFY_export_file.json', data);
});


function exportfile(name, data) {
    var urlObject = window.URL || window.webkitURL || window;
    var export_blob = new Blob([data]);
 
    var save_link = document.createElementNS("http://www.w3.org/1999/xhtml", "a")
    save_link.href = urlObject.createObjectURL(export_blob);
    save_link.download = name;
    var ev = document.createEvent("MouseEvents");
    ev.initMouseEvent(
        "click", true, false, window, 0, 0, 0, 0, 0
        , false, false, false, false, 0, null
        );
    save_link.dispatchEvent(ev);
}



