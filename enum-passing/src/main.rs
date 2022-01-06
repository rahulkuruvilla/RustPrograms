use std::sync::mpsc;
use std::thread;

//enum of different types of shopping
//represented with structs of items and their quantity
#[derive(Debug)]
enum Shopping{
    Groceries {
        bread: u8,
        milk: u8,
        potatoes: u8,
    },
    Technology {
        tablet: u8,
        laptop: u8,
        speaker: u8,
    },
    Garden {
        spade: u8,
        shovel: u8,
        pots: u8,
    }
}

impl Shopping {
    fn first_item(&self) -> u8{
        use crate::Shopping::*;
        match *self {
            Groceries {bread, milk, potatoes} => bread, 
            Technology {tablet, laptop, speaker} => tablet,
            Garden {spade, shovel, pots} => spade,
        }
    }

    fn total(&self) -> u8{
        use crate::Shopping::*;
        let sum = |x,y,z| x+y+z;
        match *self {
            Groceries {bread, milk, potatoes} => sum(bread, milk, potatoes), 
            Technology {tablet, laptop, speaker} => sum(tablet, laptop, speaker),
            Garden {spade, shovel, pots} => sum(spade, shovel, pots),
        }
    }

    fn quantity_zero(&self) -> Self{
        use crate::Shopping::*;
        match *self {
            Groceries {bread, milk, potatoes} => {
                Groceries {
                    bread: 0, 
                    milk: 0, 
                    potatoes: 0,
                }
            },
            Technology {tablet, laptop, speaker} => {
                Technology {
                    tablet: 0, 
                    laptop: 0, 
                    speaker: 0,
                } 
            },
            Garden {spade, shovel, pots} => {
                Garden {
                    spade: 0, 
                    shovel: 0, 
                    pots: 0,
                }
            },
        }
    }

    fn increment(&self) -> Self{
        use crate::Shopping::*;

        let inc = |x| x+1;
        match *self {
            Groceries {bread, milk, potatoes} => {
                Groceries {
                    bread: inc(bread), 
                    milk: inc(milk), 
                    potatoes: inc(potatoes),
                }
            },
            Technology {tablet, laptop, speaker} => {
                Technology {
                    tablet: inc(tablet), 
                    laptop: inc(laptop), 
                    speaker: inc(speaker),
                } 
            },
            Garden {spade, shovel, pots} => {
                Garden {
                    spade: inc(spade), 
                    shovel: inc(shovel), 
                    pots: inc(pots),
                }
            },
        }
    }
}

fn main() {
    // 3 spawned threads send their 'order' to the main thread
    // the main thread makes some adjustments to the order 
    // the main thread sends the order back to its respective thread 

    //create mpsc channel from spawn threads to main thread
    let (senders, reciever) = mpsc::channel();

    //THREAD 1
    let sender = senders.clone();
    let (send_to_t1, reciever1_from_main) = mpsc::channel();
    let handle1 = thread::spawn(move || {
        let first_order = Shopping::Garden {
            spade: 0,
            shovel: 2,
            pots: 4,
        };

        sender.send(first_order).unwrap();
        //val no longer belongs to this thread

        let val: Shopping = reciever1_from_main.recv().unwrap();
        println!("thread 1 got order of {:?} items from main thread", val.total());
    });

    //THREAD 2
    let sender = senders.clone();
    let (send_to_t2, reciever2_from_main) = mpsc::channel();
    let handle2 = thread::spawn(move || {
        let sec_order = Shopping::Technology {
            tablet: 1,
            laptop: 2,
            speaker: 5,
        };

        sender.send(sec_order).unwrap();
        //val no longer belongs to this thread

        let val: Shopping = reciever2_from_main.recv().unwrap();
        println!("thread 2 got order of {:?} items from main thread", val.total());
    });

    //THREAD 3
    let sender = senders.clone();
    let (send_to_t3, reciever3_from_main) = mpsc::channel();
    let handle3 = thread::spawn(move || {
        let third_order = Shopping::Groceries {
            bread: 1,
            milk: 2,
            potatoes: 1,
        };
    
        sender.send(third_order).unwrap();
        //val no longer belongs to this thread
    
        let val: Shopping = reciever3_from_main.recv().unwrap();
        println!("thread 3 got order from main thread with {:?} lots of the first item", val.first_item());
    });
    
    // main thread increments each quantity in the order from thread 1 by 1
    let mut order_from_t1 = reciever.recv().unwrap();
    println!("order_from_t1 {:?}", order_from_t1);
    order_from_t1 = order_from_t1.increment();
    println!("order_from_t1 incremented {:?}", order_from_t1);
    send_to_t1.send(order_from_t1).unwrap();

    // main thread sets each quantity in the order from thread 2 to 0
    let mut order_from_t2 = reciever.recv().unwrap();
    println!("order_from_t2 {:?}", order_from_t2);
    order_from_t2 = order_from_t2.quantity_zero();
    println!("order_from_t2 zero'ed {:?}", order_from_t2);
    send_to_t2.send(order_from_t2).unwrap();

    // main thread increments each quantity in the order from thread 3 by 1
    let mut order_from_t3 = reciever.recv().unwrap();
    println!("order_from_t3 {:?}", order_from_t3);
    order_from_t3 = order_from_t3.increment();
    println!("order_from_t3 incremented {:?}", order_from_t3);
    send_to_t3.send(order_from_t3).unwrap();

    //main thread waits for each each thread to finish
    handle1.join();
    handle2.join();
    handle3.join();
}
