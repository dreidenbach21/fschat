#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Aug  2 10:01:56 2019

@author: dannyreidenbach
"""

import tensorflow as tf
from tensorflow import keras

import numpy as np
import matplotlib.pyplot as plt

#LEARN THE MAT PLOT COMMANDS TO UNDERSTAND THE WORK BEHIND THE PLOTTING

print(tf.__version__)

# getting the data which is already a part of Tensor Flow
fashion_mnist = keras.datasets.fashion_mnist

(train_images, train_labels), (test_images, test_labels) = fashion_mnist.load_data()

#The images are 28x28 NumPy arrays, with pixel values ranging between 0 and 255. 
#The labels are an array of integers, ranging from 0 to 9. These correspond to the class of clothing the image represents

class_names = ['T-shirt/top', 'Trouser', 'Pullover', 'Dress', 'Coat',
               'Sandal', 'Shirt', 'Sneaker', 'Bag', 'Ankle boot']


#using math plot to be able to visualize the images of the trainiong set
plt.figure()
plt.imshow(train_images[28])
plt.colorbar()
plt.grid(False)
plt.show()

#pre processing all the images so that all the pixel values range [0,1]
train_images = train_images / 255.0
test_images = test_images / 255.0

plt.figure(figsize=(10,10))
for i in range(25):
    plt.subplot(5,5,i+1)
    plt.xticks([])
    plt.yticks([])
    plt.grid(False)
    plt.imshow(train_images[i], cmap=plt.cm.binary)
    plt.xlabel(class_names[train_labels[i]])
plt.show()

#setting up the layers of a neural network

model = keras.Sequential([
    keras.layers.Flatten(input_shape=(28, 28)),
    keras.layers.Dense(128, activation=tf.nn.relu),
    keras.layers.Dense(10, activation=tf.nn.softmax)
])
    #The first layer in this network, tf.keras.layers.Flatten
    #transforms the format of the images from a 2d-array (of 28 by 28 pixels)
    #to a 1d-array of 28 * 28 = 784 pixels.
    
    #the network consists of a sequence of two tf.keras.layers.Dense layers.
    #These are densely-connected, or fully-connected, neural layers. The first
    #Dense layer has 128 nodes (or neurons). The second (and last) layer is a 
    #10-node softmax layer—this returns an array of 10 probability scores that sum to 1. 
    #Each node contains a score that indicates the probability 
    #that the current image belongs to one of the 10 classes.
    
    
# HOW TO IMPROVE THE ACCURACY OF THE MINST DATA SET
    
# I think this method does a lot of stuff with built in things insrtead of having to right hte functions themself
    
model.compile(optimizer='adam',
              loss='sparse_categorical_crossentropy',
              metrics=['accuracy'])

# Now the model is to be trained with the training data

#1.Feed the training data to the model—in this example, the train_images and train_labels arrays.
#2.The model learns to associate images and labels.
#3.We ask the model to make predictions about a test set—in this example, the test_images array. 
    #We verify that the predictions match the labels from the test_labels array.

model.fit(train_images, train_labels, epochs=6) #1 an epoch is the number of times the model is trained over the entire training
    #data set
    # the more epochs the more training the model does and the higher accuracy is reaches for the test data

test_loss, test_acc = model.evaluate(test_images, test_labels)

print('Test accuracy:', test_acc)

# the test accuracy is less than the training accuracy due ot over fitting


# PREDICTIONS ON THE TEST IMAGES
predictions = model.predict(test_images)
#A prediction is an array of 10 numbers.
#These describe the "confidence" of the model that the image corresponds to each 
#of the 10 different articles of clothing. We can see which label has the highest confidence value

#PLOTTING OF THE ARTICLES

def plot_image(i, predictions_array, true_label, img): #How to plot the left Image
  predictions_array, true_label, img = predictions_array[i], true_label[i], img[i]
  plt.grid(False)
  plt.xticks([])
  plt.yticks([])
  
  plt.imshow(img, cmap=plt.cm.binary)
  
  predicted_label = np.argmax(predictions_array)
  if predicted_label == true_label:
    color = 'blue'
  else:
    color = 'red'
  
  plt.xlabel("{} {:2.0f}% ({})".format(class_names[predicted_label],
                                100*np.max(predictions_array),
                                class_names[true_label]),
                                color=color)

def plot_value_array(i, predictions_array, true_label): #How to plot the right Image
  predictions_array, true_label = predictions_array[i], true_label[i]
  plt.grid(False)
  plt.xticks([])
  plt.yticks([])
  thisplot = plt.bar(range(10), predictions_array, color="#777777")
  plt.ylim([0, 1])
  predicted_label = np.argmax(predictions_array)
  
  thisplot[predicted_label].set_color('red')
  thisplot[true_label].set_color('blue')
  

i = 5
plt.figure(figsize=(6,3))
plt.subplot(1,2,1)
plot_image(i, predictions, test_labels, test_images)
plt.subplot(1,2,2)
plot_value_array(i, predictions,  test_labels)
plt.show()

num_rows = 5
num_cols = 3
num_images = num_rows*num_cols
plt.figure(figsize=(2*2*num_cols, 2*num_rows))
for i in range(num_images):
  plt.subplot(num_rows, 2*num_cols, 2*i+1)
  plot_image(i, predictions, test_labels, test_images)
  plt.subplot(num_rows, 2*num_cols, 2*i+2)
  plot_value_array(i, predictions, test_labels)
plt.show()