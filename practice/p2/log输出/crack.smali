.class public Lcrack;
.super Ljava/lang/Object;
.source "crack.java"
 
.method public static log(Ljava/lang/String;)V
    .locals 1
    .prologue
 
    const-string v0, "==Debug-Info=="
    invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method

 .method public static userlog(Ljava/lang/String;)V
    .locals 1
    .prologue
 
    const-string v0, "user==Debug-Info=="
    invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method

 .method public static passlog(Ljava/lang/String;)V
    .locals 1
    .prologue
 
    const-string v0, "pass==Debug-Info=="
    invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method

 .method public static aeslog(Ljava/lang/String;)V
    .locals 1
    .prologue
 
    const-string v0, "aes==Debug-Info=="
    invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method


.method public static convertByteArrayToString([B)Ljava/lang/String;
    .locals 7

    const/4 v1, 0x0

    new-instance v2, Ljava/lang/StringBuffer;

    invoke-direct {v2}, Ljava/lang/StringBuffer;-><init>()V

    array-length v3, p0

    move v0, v1

    :goto_0
    if-lt v0, v3, :cond_0

    invoke-virtual {v2}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    move-result-object v0
    
    const-string v6, "==Debug-Info=="
    
    invoke-static {v6, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    

    return-object v0

    :cond_0
    aget-byte v4, p0, v0

    const-string v5, "0x%02X"

    const/4 v6, 0x1

    new-array v6, v6, [Ljava/lang/Object;

    invoke-static {v4}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object v4

    aput-object v4, v6, v1

    invoke-static {v5, v6}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v4}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    add-int/lit8 v0, v0, 0x1

    goto :goto_0
.end method