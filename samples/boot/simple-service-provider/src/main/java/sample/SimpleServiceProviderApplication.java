/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package sample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SimpleServiceProviderApplication implements CommandLineRunner {

	public static void main(String[] args) throws ClassNotFoundException {
		SpringApplication.run(SimpleServiceProviderApplication.class, args);
	}

  @Autowired
  private SecMgrPerformanseTest secMgrPerformanseTest;

  @Override
  public void run(String... args) throws Exception {
	  // pass params via:
    // ./gradlew -b ./samples/boot/simple-service-provider/build.gradle bootRun --args 'param1 param2'
    if (args.length > 0 && args[0].equalsIgnoreCase("--perftest")) {
      secMgrPerformanseTest.startLoad();
    }
  }
}
