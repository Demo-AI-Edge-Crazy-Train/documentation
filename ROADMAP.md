# Roadmap for the Demo

## 1. Handle properly the Kafka connection timeout

Why: The AI predictions are not done when the Kafka connection is not reliable.

## 2. Convert the Red Hat Device Edge images generation to bootc

Why: os-builder is beeing replaced by bootc

## 3. Update the RHDE images to use the new Nvidia Kernel modules

Why: NVidia now releases the kernel modules for RHEL publicly.

## 4. Cleanup the documentation

Why: currently written in French and quite rough.

## 5. Backport the fixes to noble and node-poweredup

Why: I had to patch those libraries to make the bluetooth work.

## 6. Implement a PID algorithm to regulate the speed of the train

Why: when the batteries are running low, the train is stuck in corners.

## 7. Implement the GitOps on the train

Why: currently, the microservices on the train are deployed manually (`oc apply -f ...`)

## 8. Implement obstacle detection on the train lane

Why: all customers want the train to stop when there are obstacles on the train lane.

## 9. Add Generative AI using OpenShift AI

For example: when the train stops because of an obstacle on the lane, a message is announced in the train station to warn about possible delays.

## 10. Add support for inference using AMD hardware (either CPU or GPU)

Why: currently the AI Pod is based on Ubuntu. Using AMD for inference might help us use UBI instead.
