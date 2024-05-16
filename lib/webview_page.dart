import 'package:flutter/material.dart';
import 'package:http/http.dart';
import 'package:loading_animation_widget/loading_animation_widget.dart';

import 'package:http/http.dart' as http;

class WebviewPage extends StatefulWidget {
  const WebviewPage({super.key, required this.title});

  final String title;

  @override
  State<WebviewPage> createState() => _WebviewPageState();
}

class _WebviewPageState extends State<WebviewPage> {

  var url = Uri.http('192.168.1.100', '/hello');

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Center(

        // Since we're just fetching static content right now, a FutureBuild will be OK
        // Later we may want to use a state management framework such as BLoC.
        //
        child: FutureBuilder<Response>(
          future: http.post(url),
          builder: (BuildContext context, AsyncSnapshot<Response> snapshot) {
            if (snapshot.hasData) {

              // Show the text of the web page.
              //
              return SingleChildScrollView(child: Html(data: snapshot.data!.body));
            }
            else {

              // While waiting for the page to fetch, show a loading animation
              //
              return LoadingAnimationWidget.waveDots(
                color: Theme.of(context).primaryColor,
                size: 200,
              );
            }
          }
        ),
      ),
    );
  }
}