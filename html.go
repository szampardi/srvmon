package main

const (
	header string = `
<!doctype html>
<html lang="en">
   <style type="text/css">
      body { background: black !important; }
   </style>
   <meta charset="utf-8">
   <meta http-equiv="refresh" content="60">
   <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
   <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
   <title>{{.PageTitle}}</title>
   <body>
      <div class="container bg-dark text-white">
         <div class=row> 
            <div class=col>
            <h1>{{.PageTitle}}</h1>
            </div>
         </div>
         <div class=row>
            <div class=col>
`
	footer string = `
         <br>
         <div class=row>
            <div class=col>
               <p class=small>{{timestamp}}  
                  <br>Total duration: {{.Duration}}
               </p>
            </div>
         </div>
      </div>
   </body>
</html>
`
	successfulChecks string = `
         <div class=row>
            <div class=col>
{{- range .Results}}{{- if eq .Error ""}}
               <a href="#" class="btn btn-success disabled" tabindex="-1" role="button" aria-disabled="true" style="margin-top: 10px; padding: 10px;">{{.Target.Category}}[{{.Target.ID}}]<font color=LightGray>({{.Duration}})</font></a> &nbsp;
{{- end}}{{- end}}
            </div>
         </div>
`
	failedChecks string = `{{if ne .Failures 0}}
               <div class="alert alert-danger" role="alert">
               {{.Failures}} check(s) have failed.
               </div>
               <table class="table">
                  <thead class="bg-dark text-white">
                     <tr>
                        <th>Category[ID]</th>
                        <th>TotalAttemtps/Status/Expected</th>
                        <th>Error</th>
                        <th>Duration</th>
                     </tr>
                  </thead>
                  <tbody>
{{- range .Results}}
  {{- if .Error}}
                     <tr class="table-danger">
                        <td>{{.Target.Category}}[{{.Target.ID}}]</td>
                        <td>{{- math .Target.RetryAttempts "+" 1 }} / {{- .StatusCode }} / {{.Target.ExpectedStatusCode}}</td>
                        <td>{{.Error}}</td>
                        <td>{{.Duration}}</td>
                     </tr>
  {{- end}}
{{- end}}
                  </tbody>
               </table>
{{- else}}
                     <div class="alert alert-success" role="alert">All is well, all {{len .Results}} services are up.</div>
{{- end}}
            </div>
         </div>
`
)

var templates = map[string]string{
	"header":           header,
	"footer":           footer,
	"failedChecks":     failedChecks,
	"successfulChecks": successfulChecks,
	"index": `{{$results := checkAll .Targets .ConcurrentChecks}}
{{- template "header" .}}
{{- template "failedChecks" $results}}
{{- template "successfulChecks" $results}}
{{- template "footer" $results}}`,
}
