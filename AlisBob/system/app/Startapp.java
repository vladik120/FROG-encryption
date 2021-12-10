package app;

import controller.AppController;
import javafx.application.Application;
import javafx.stage.Stage;

public class Startapp extends Application {

	public static void main(String args[]) throws Exception {
		launch(args);
	}


	@Override
	public void start(Stage primaryStage) throws Exception {
		AppController aFrame = new AppController();
		aFrame.start(primaryStage);
	}

}

