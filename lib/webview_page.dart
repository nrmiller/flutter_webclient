import 'dart:convert';
import 'dart:io';

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
  //
  // Future<String> post(String url, Map jsonMap) async {
  //   HttpClient httpClient = new HttpClient();
  //   HttpClientRequest request = await httpClient.postUrl(Uri.parse(url));
  //   request.headers.set('Content-Type', 'application/json');
  //   request.add(utf8.encode(json.encode(jsonMap)));
  //
  //   HttpClientResponse response = await request.close();
  //   // todo - you should check the response.statusCode
  //
  //   String reply = await response.transform(utf8.decoder).join();
  //   httpClient.close();
  //   return reply;
  // }

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
          // future: http.get(Uri.https('nicholas-VirtualBox.localdomain', '/hello')),
          // future: http.post(Uri.https('nicholas-VirtualBox.localdomain', '/reset')),
          // future: http.post(Uri.https('nicholas-VirtualBox.localdomain', '/hello'), // application/x-www-form-urlencoded
          //     body: <String, String>{ 'setValue': '333' }
          // ),
          future: http.post(Uri.https('nicholas-VirtualBox.localdomain', '/hello'),
              headers: {
                'Content-Type': 'text/plain',
              },
              body: jsonEncode({
                'setValue': '777',
              })
            ),
          builder: (BuildContext context, AsyncSnapshot<Response> snapshot) {
            if (snapshot.hasData) {

              // Show the text of the web page.
              //
              return SingleChildScrollView(child: Text(snapshot.data!.body));
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