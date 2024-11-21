document.addEventListener('DOMContentLoaded', function() {
    // Replace with the dynamic URL of the PDF you want to load
    var pdfUrl = '{{ pdf_url }}';  // This will be rendered by Flask in the template
    var pdfContainer = document.getElementById('pdf-container');

    // Set the workerSrc property for PDF.js
    pdfjsLib.GlobalWorkerOptions.workerSrc = '{{ url_for("static", filename="js/pdfjs/pdf.worker.js") }}';

    // Initialize PDFAnnotate
    var pdfAnnotate = new PDFAnnotate('pdf-container', pdfUrl, {
        ready: function() {
            // Load existing annotations after the PDF is rendered
            loadAnnotations();
        }
    });

    // Function to load existing annotations from the server
    function loadAnnotations() {
        var pdfId = {{ pdf_id }}; // Pass the PDF ID from Flask
        fetch('/api/get_annotations/' + pdfId)
            .then(response => response.json())
            .then(data => {
                data.annotations.forEach(annotation => {
                    pdfAnnotate.addAnnotation(annotation.data);
                });
            })
            .catch(error => {
                console.error('Error loading annotations:', error);
            });
    }

    // Handle annotation events
    pdfAnnotate.setStoreAdapter(new PDFAnnotate.LocalStoreAdapter());

    // Save annotations to the server when added or modified
    pdfAnnotate.on('annotation:add', function(data) {
        saveAnnotation(data);
    });

    // Function to save a new annotation to the server
    function saveAnnotation(annotationData) {
        var pdfId = {{ pdf_id }}; // Pass the PDF ID from Flask
        fetch('/api/save_annotation', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                pdf_id: pdfId,
                annotation_data: annotationData
            })
        })
        .then(response => response.json())
        .then(data => {
            console.log('Annotation saved:', data);
        })
        .catch(error => {
            console.error('Error saving annotation:', error);
        });
    }
});
