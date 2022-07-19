///usr/bin/env jbang "$0" "$@" ; exit $? 
//DEPS software.amazon.awssdk:cloudtrail:2.17.233

import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.*;

import java.time.Instant;
import java.util.List;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

class cloudTrailEvents {

    public static Instant lastTime = null;

    public static void main(String[] args) {
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
        CloudTrailTask task1 = new CloudTrailTask ("CloudTrail Task", args[0]);

        executor.scheduleAtFixedRate(task1, 1, 20, TimeUnit.SECONDS);
    }

    protected static class CloudTrailTask implements Runnable
    {
        private String name;
        private String region;

        public CloudTrailTask(String name) {
            this.name = name;
        }

        public CloudTrailTask(String name, String region) {
            this.name = name;
            this.region = region;
        }

        public String getName() {
            return name;
        }

        @Override
        public void run()
        {
            Region regionValue = Region.of(region);
            CloudTrailClient cloudTrailClient = CloudTrailClient.builder()
                    .region(regionValue)
                    .credentialsProvider(ProfileCredentialsProvider.create())
                    .build();
                try {
                    LookupEventsRequest.Builder eventsRequestBuilder = LookupEventsRequest.builder()
                            .maxResults(100).lookupAttributes(LookupAttribute.builder().attributeKey(LookupAttributeKey.EVENT_SOURCE).attributeValue("secretsmanager.amazonaws.com").build());

                    if (lastTime != null) {
                        eventsRequestBuilder.startTime(lastTime.plusMillis(1000));
                    }

                    LookupEventsRequest lookupEventsRequest = eventsRequestBuilder.build();

                    LookupEventsResponse response = cloudTrailClient.lookupEvents(lookupEventsRequest);
                    List<Event> events = response.events();

                    if (events.size() > 0) {
                        lastTime = events.get(0).eventTime();
                    }

                    System.err.println("Events are " + events.size());
                    for (Event event : events) {
                        if (event.eventSource().equalsIgnoreCase("secretsmanager.amazonaws.com")) {
                            System.out.println("Event name is : " + event.eventName());
                            System.out.println("Event name is : " + event.resources().toString());
                            System.out.println("The event source is : " + event.eventSource());
                            System.out.println("The event time is: " + event.eventTime().toString());
                        }
                    }

                } catch (CloudTrailException e) {
                    System.err.println(e.getMessage());
                    System.exit(1);
                }
        }
    }
}
